package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type IdentityAgentClient struct {
	Client *http.Client
}

var provModule map[string]map[string]interface{} = map[string]map[string]interface{}{
	"external": {
		"caCerts":  "",
		"id":       "",
		"password": "",
		"uri":      []string{},
	},
}

var ldapAuthModule map[string]map[string]interface{} = map[string]map[string]interface{}{
	"ldapauth": {
		"ldapBindPwd":               "",
		"ldapBindDn":                "",
		"ldapCACerts":               "",
		"ldapConnIdleTime":          0,
		"ldapConnMaxTime":           0,
		"ldapFetchAttributes":       []string{},
		"ldapFetchBinaryAttributes": []string{},
		"ldapMaxConnections":        0,
		"ldapRequestTimeout":        0,
		"ldapSearchBase":            "o=ibm,c=us",
		"ldapStartTls":              false,
		"ldapUri":                   []string{},
		"ldapUsernameAttribute":     "",
		"ldapUserSearchObjectclass": []string{},
	},
}

var extauthnModule map[string]map[string]interface{} = map[string]map[string]interface{}{
	"extauthn": {
		"authentication": map[string]interface{}{
			"type": "",
			"basic": map[string]interface{}{
				"username": "",
				"password": "",
			},
		},

		"caCerts":         "",
		"uris":            []string{},
		"fetchAttributes": []string{},
	},
}

type IdentityAgentListResponse = []openapi.OnpremAgentConfiguration

type IdentityAgentConfig = openapi.OnpremAgentConfiguration

func NewIdentityAgentClient() *IdentityAgentClient {
	return &IdentityAgentClient{}
}

func AddModule(identityAgent *IdentityAgentConfig, identityType string) {
	identityAgent.Purpose = (*openapi.OnpremAgentConfigurationPurpose)(&identityType)
	if identityType == "PROV" {
		identityAgent.Modules = append(identityAgent.Modules, provModule)
	} else if identityType == "LDAPAUTH" {
		identityAgent.Modules = append(identityAgent.Modules, ldapAuthModule)
	} else if identityType == "EXTAUTHN" {
		identityAgent.Modules = append(identityAgent.Modules, extauthnModule)
	}
}

func (c *IdentityAgentClient) CreateIdentityAgent(ctx context.Context, IdentityAgentConfig *IdentityAgentConfig) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to create Identity Agent")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	body, err := json.Marshal(IdentityAgentConfig)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal Identity Agent data; err=%v", err)
		return "", defaultErr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.CreateOnpremAgentWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create Identity Agent; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Identity Agent"); err != nil {
			vc.Logger.Errorf("unable to create the Identity Agent; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	resourceURI := ""
	resourceURI = response.HTTPResponse.Header.Get("Location")

	return resourceURI, nil
}

func (c *IdentityAgentClient) GetIdentityAgentByID(ctx context.Context, identityAgentID string) (*IdentityAgentConfig, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetOnpremAgentWithResponse(ctx, identityAgentID, &openapi.GetOnpremAgentParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agent; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Identity agent"); err != nil {
			vc.Logger.Errorf("unable to get the Identity agent; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Identity agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the Identity agent with identityAgentID %s; status=%d", identityAgentID, response.StatusCode())
	}

	identityAgent := &IdentityAgentConfig{}
	if err = json.Unmarshal(response.Body, identityAgent); err != nil {
		return nil, "", errorsx.G11NError("unable to get the Identity agent")
	}

	return identityAgent, response.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentityAgentClient) GetIdentityAgents(ctx context.Context, search string, page int, limit int) (*IdentityAgentListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.ListOnpremAgentsParams{}
	if len(search) > 0 {
		params.Search = &search
	}

	pagination := url.Values{}
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}

	if len(pagination) > 0 {
		paginationStr := pagination.Encode()
		params.Pagination = &paginationStr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.ListOnpremAgents(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
		return nil, "", err
	}
	defer func() { _ = response.Body.Close() }()

	buf, err := io.ReadAll(response.Body)

	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		fmt.Println(response.StatusCode)
		if err := errorsx.HandleCommonErrors(ctx, response, "unable to get Identity agents"); err != nil {
			vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
			return nil, "", err
		}
		data, _ := io.ReadAll(response.Body)
		vc.Logger.Errorf("unable to get the Identity agents; code=%d, body=%s", response.StatusCode, string(data))
		return nil, "", errorsx.G11NError("unable to get the Identity agents")
	}

	identityAgentResponse := &IdentityAgentListResponse{}
	if err = json.Unmarshal(buf, &identityAgentResponse); err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s, body=%s", err)
		return nil, "", errorsx.G11NError("unable to get the Identity agents")
	}

	return identityAgentResponse, response.Request.URL.String(), nil
}

func (c *IdentityAgentClient) UpdateIdentityAgent(ctx context.Context, identityAgentsConfig *IdentityAgentConfig) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	body, err := json.Marshal(identityAgentsConfig)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the Identity Agent; err=%v", err)
		return errorsx.G11NError("unable to marshal the Identity Agent; err=%v", err)
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.UpdateOnpremAgentWithBodyWithResponse(ctx, *identityAgentsConfig.ID, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to update Identity Agent"); err != nil {
			vc.Logger.Errorf("unable to update the Identity Agent; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("unable to update Identity Agent; err=%v", err)
		return errorsx.G11NError("unable to update Identity Agent; err=%v", err)
	}
	if response.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("failed to update Identity Agent ; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil
}

func (c *IdentityAgentClient) DeleteIdentityAgentByID(ctx context.Context, identityAgentID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.DeleteOnpremAgentWithResponse(ctx, identityAgentID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete Identity Agent; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Identity Agent; err=%s", err.Error())
	}
	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete Identity Agent"); err != nil {
			vc.Logger.Errorf("unable to delete the Identity Agent; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the Identity Agent; err=%s", err.Error())
		}
		vc.Logger.Errorf("unable to delete the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("unable to delete the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}
	return nil
}
