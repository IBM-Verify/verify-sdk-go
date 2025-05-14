package authentication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type IdentitySourceClient struct {
	Client *http.Client
}

type IdentitySource = openapi.IdentitySourceInstancesData
type IdentitySourceList = openapi.IdentitySourceIntancesDataList

type SignInOptions struct {
	InstanceName string                   `json:"instanceName" yaml:"instanceName"`
	Properties   []map[string]interface{} `json:"properties" yaml:"properties"`
}

func NewIdentitySourceClient() *IdentitySourceClient {
	return &IdentitySourceClient{}
}

func (c *IdentitySourceClient) CreateIdentitySource(ctx context.Context, identitySource *IdentitySource) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to create identitySource")

	body, err := json.Marshal(identitySource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitySource data; err=%v", err)
		return "", defaultErr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.CreateIdentitySourceV2WithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create identitySource; err=%v", err)
		return "", defaultErr
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create identitySource"); err != nil {
			vc.Logger.Errorf("unable to create the identitySource; err=%s", err.Error())
			return "", errorsx.G11NError("unable to create the identitySource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("unable to create the identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	uri, _ := resp.HTTPResponse.Location()
	return uri.String(), nil
}

func (c *IdentitySourceClient) GetIdentitySourceByID(ctx context.Context, identitySourceID string) (*IdentitySource, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetInstanceV2WithResponse(ctx, identitySourceID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the IdentitySource")
	}

	IdentitySource := &IdentitySource{}
	if err = json.Unmarshal(resp.Body, IdentitySource); err != nil {
		return nil, "", errorsx.G11NError("unable to get the IdentitySource")
	}

	return IdentitySource, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentitySourceClient) GetIdentitySources(ctx context.Context, sort string, count string) (*IdentitySourceList, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.GetInstancesV2Params{}
	if len(sort) > 0 {
		params.Sort = &sort
	}
	if len(count) > 0 {
		params.Count = &count
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetInstancesV2WithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySources; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get IdentitySources"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySources; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the IdentitySources; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the IdentitySources")
	}

	IdentitySourcesResponse := &IdentitySourceList{}
	if err = json.Unmarshal(resp.Body, &IdentitySourcesResponse); err != nil {
		vc.Logger.Errorf("unable to get the IdentitySources; err=%s, body=%s", err, string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the IdentitySources")
	}

	return IdentitySourcesResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentitySourceClient) DeleteIdentitySourceByID(ctx context.Context, identitySourceID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.DeleteIdentitySourceV2WithResponse(ctx, identitySourceID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the IdentitySource; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the IdentitySource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *IdentitySourceClient) UpdateIdentitySource(ctx context.Context, identitySourceID string, identitySource *IdentitySource) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to update identitySource")
	body, err := json.Marshal(identitySource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitySource data; err=%v", err)
		return defaultErr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.UpdateIdentitySourceV2WithBodyWithResponse(ctx, identitySourceID, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update Identity provider"); err != nil {
			vc.Logger.Errorf("unable to update the Identity provider; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("unable to update identitySource; err=%v", err)
		return errorsx.G11NError("unable to update identitySource; err=%v", err)
	}

	if resp.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update identitySource ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *IdentitySourceClient) GetIdentitySourceID(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	search := fmt.Sprintf(`instanceName = "%s"`, name)
	params := &openapi.GetInstancesV2Params{
		Search: &search,
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, _ := client.GetInstancesV2WithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySource with identitySourceName %s; err=%s", name, err.Error())
			return "", errorsx.G11NError("unable to get the IdentitySource with identitySourceName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return "", errorsx.G11NError("failed to parse response: %w", err)
	}

	resources, ok := data["identitySources"].([]interface{})
	if !ok || len(resources) == 0 {
		return "", errorsx.G11NError("no identitySource found with identitySourceName %s", name)
	}

	firstResource, ok := resources[0].(map[string]interface{})
	if !ok {
		return "", errorsx.G11NError("invalid resource format")
	}

	// Extract "id" field
	id, ok := firstResource["id"].(string)
	if !ok {
		return "", errorsx.G11NError("ID not found or invalid type")
	}

	return id, nil
}

func (c *IdentitySourceClient) UpdateSignInOptions(ctx context.Context, identitySource *IdentitySource) error {
	vc := contextx.GetVerifyContext(ctx)
	if identitySource.InstanceName == "" {
		vc.Logger.Errorf("instanceName cannot be empty")
		return errorsx.G11NError("instanceName cannot be empty")
	}
	ID, err := c.GetIdentitySourceID(ctx, identitySource.InstanceName)
	if err != nil {
		vc.Logger.Errorf("unable to get the identitySource ID; err=%s", err.Error())
		return errorsx.G11NError("unable to get the identitySource ID; err=%s", err.Error())
	}
	identitySourceNew, _, err := c.GetIdentitySourceByID(ctx, ID)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySource with instanceName %s; err=%s", identitySource.InstanceName, err.Error())
		return errorsx.G11NError("unable to get the IdentitySource with instanceName %s; err=%s", identitySource.InstanceName, err.Error())
	}
	identitySourceNew.Properties = identitySource.Properties

	if err := c.UpdateIdentitySource(ctx, ID, identitySourceNew); err != nil {
		vc.Logger.Errorf("unable to update the IdentitySource with instanceName %s; err=%s", identitySource.InstanceName, err.Error())
		return errorsx.G11NError("unable to update the IdentitySource with instanceName %s; err=%s", identitySource.InstanceName, err.Error())
	}

	return nil
}

// This function helps in boilerplate generation to update Sign in options
func GetSignInOptions() *SignInOptions {
	var signInOptions *SignInOptions = &SignInOptions{
		InstanceName: "",
		Properties: []map[string]interface{}{
			{
				"key":       "show_admin_user",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_admin_user_qr",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_admin_user_fido",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user_qr",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user_fido",
				"value":     "false",
				"sensitive": false,
			},
		},
	}
	return signInOptions
}
