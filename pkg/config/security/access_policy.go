package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

// Root structure
type PolicyListResponse struct {
	Total    int       `json:"total" yaml:"total"`
	Count    int       `json:"count" yaml:"count"`
	Limit    int       `json:"limit" yaml:"limit"`
	Page     int       `json:"page" yaml:"page"`
	Policies []*Policy `json:"policies" yaml:"policies"`
}

// Policy structure
type Policy struct {
	ID                    int              `json:"id" yaml:"id"`
	Name                  string           `json:"name" yaml:"name"`
	Description           string           `json:"description" yaml:"description"`
	Rules                 []*Rule          `json:"rules" yaml:"rules"`
	Meta                  AccesspolicyMeta `json:"meta" yaml:"meta"`
	Validations           Validations      `json:"validations" yaml:"validations"`
	RequiredSubscriptions []string         `json:"requiredSubscriptions" yaml:"requiredSubscriptions"`
}

// Rule structure
type Rule struct {
	ID          string       `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string       `json:"name" yaml:"name"`
	Description string       `json:"description" yaml:"description"`
	AlwaysRun   bool         `json:"alwaysRun" yaml:"alwaysRun"`
	FirstFactor bool         `json:"firstFactor" yaml:"firstFactor"`
	Conditions  []*Condition `json:"conditions" yaml:"conditions"`
	Result      Result       `json:"result" yaml:"result"`
}

// Condition represents a policy condition
type Condition struct {
	Type       string        `json:"type" yaml:"type"`
	Values     []string      `json:"values,omitempty" yaml:"values,omitempty"`
	Enabled    *bool         `json:"enabled,omitempty" yaml:"enabled,omitempty"`       // Nullable boolean
	Opcode     *string       `json:"opCode,omitempty" yaml:"opCode,omitempty"`         // Nullable string
	Attributes []*Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"` // Nested attributes
}

// Attribute represents an attribute within a condition
type Attributes struct {
	Name   string   `json:"name" yaml:"name"`
	Opcode string   `json:"opCode" yaml:"opCode"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// Result structure
type Result struct {
	Action            string              `json:"action" yaml:"action"`
	ServerSideActions []*ServerSideAction `json:"serverSideActions" yaml:"serverSideActions"`
	AuthnMethods      []string            `json:"authnMethods" yaml:"authnMethods"`
}

// ServerSideAction structure
type ServerSideAction struct {
	ActionID string `json:"actionId" yaml:"actionId"`
	Version  string `json:"version" yaml:"version"`
}

// Meta structure
type AccesspolicyMeta struct {
	State               string   `json:"state" yaml:"state"`
	Schema              string   `json:"schema" yaml:"schema"`
	Revision            int      `json:"revision" yaml:"revision"`
	Label               string   `json:"label" yaml:"label"`
	Predefined          bool     `json:"predefined" yaml:"predefined"`
	Created             int64    `json:"created" yaml:"created"`
	CreatedBy           string   `json:"createdBy" yaml:"createdBy"`
	LastActive          int64    `json:"lastActive" yaml:"lastActive"`
	Modified            int64    `json:"modified" yaml:"modified"`
	ModifiedBy          string   `json:"modifiedBy" yaml:"modifiedBy"`
	Scope               []string `json:"scope" yaml:"scope"`
	EnforcementType     string   `json:"enforcementType" yaml:"enforcementType"`
	ReferencedBy        []string `json:"referencedBy,omitempty" yaml:"referencedBy,omitempty"`
	References          []string `json:"references,omitempty" yaml:"references,omitempty"`
	TenantDefaultPolicy bool     `json:"tenantDefaultPolicy" yaml:"tenantDefaultPolicy"`
}

// Validations structure
type Validations struct {
	SubscriptionsNeeded []string `json:"subscriptionsNeeded" yaml:"subscriptionsNeeded"`
}

type PolicyClient struct {
	Client *http.Client
}

func NewAccesspolicyClient() *PolicyClient {
	return &PolicyClient{}
}

func (c *PolicyClient) CreateAccessPolicy(ctx context.Context, accessPolicy *Policy) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := fmt.Errorf("unable to create accesspolicy")

	b, err := json.Marshal(accessPolicy)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal accesspolicy data; err=%v", err)
		return "", defaultErr
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.CreateAccessPolicyWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(b), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create accesspolicy; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to create accesspolicy"); err != nil {
			vc.Logger.Errorf("unable to create the accesspolicy; err=%s", err.Error())
			return "", fmt.Errorf("unable to create the accesspolicy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the accesspolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", fmt.Errorf("unable to create the accesspolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(response.Body, &m); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	id, ok := m["id"].(float64)
	if !ok {
		return "", fmt.Errorf("failed to parse 'id' as float64")
	}

	return fmt.Sprintf("%s/%d", response.HTTPResponse.Request.URL.String(), int(id)), nil
}

func (c *PolicyClient) GetAccesspolicy(ctx context.Context, accesspolicyName string) (*Policy, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	idStr, err := c.getAccesspolicyId(ctx, accesspolicyName)
	if err != nil {
		vc.Logger.Errorf("unable to get the access policy ID; err=%s", err.Error())
		return nil, "", err
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		vc.Logger.Errorf("unable to get the access policy ID; err=%s", err.Error())
		return nil, "", err
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.GetAccessPolicyWithResponse(ctx, int64(id), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	Accesspolicy := &Policy{}
	if err = json.Unmarshal(response.Body, Accesspolicy); err != nil {
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	return Accesspolicy, response.HTTPResponse.Request.URL.String(), nil
}

func (c *PolicyClient) GetAccesspolicies(ctx context.Context) (*PolicyListResponse, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.ListAccessPoliciesWithResponse(ctx, &openapi.ListAccessPoliciesParams{}, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policies"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policies; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policies")
	}

	AccesspoliciesResponse := &PolicyListResponse{}
	if err = json.Unmarshal(response.Body, &AccesspoliciesResponse); err != nil {
		vc.Logger.Errorf("unable to get the Accesspolicies; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Accesspolicies")
	}

	return AccesspoliciesResponse, response.HTTPResponse.Request.URL.String(), nil
}

func (c *PolicyClient) DeleteAccesspolicyByID(ctx context.Context, policyID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	ID, err := strconv.Atoi(policyID)
	if err != nil {
		vc.Logger.Errorf("unable to get the access policy ID; err=%s", err.Error())
		return err
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.DeleteAccessPolicyWithResponse(ctx, int64(ID), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
	}

	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete Access Policy"); err != nil {
			vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
			return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return fmt.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil
}

func (c *PolicyClient) UpdateAccesspolicy(ctx context.Context, accesspolicy *Policy) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}

	b, err := json.Marshal(accesspolicy)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return fmt.Errorf("unable to marshal the patch request; err=%v", err)
	}

	response, err := client.UpdateAccessPolicyWithBodyWithResponse(ctx, int64(accesspolicy.ID), "", bytes.NewBuffer(b), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update accesspolicy; err=%v", err)
		return fmt.Errorf("unable to update accesspolicy; err=%v", err)
	}
	if response.StatusCode() != http.StatusCreated {
		vc.Logger.Errorf("failed to update accesspolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return fmt.Errorf("failed to update accesspolicy ; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil
}

func (c *PolicyClient) getAccesspolicyId(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	search := fmt.Sprintf(`name = "%s"`, name)
	params := &openapi.ListAccessPoliciesParams{
		Search: &search,
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, _ := client.ListAccessPoliciesWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy with accesspolicyName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the Access Policy with accesspolicyName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	policies, ok := data["policies"].([]interface{})
	if !ok || len(policies) == 0 {
		return "", fmt.Errorf("no accesspolicy found with accesspolicyName %s", name)
	}

	firstResource, ok := policies[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid resource format")
	}

	// Extract "id" field
	id, ok := firstResource["id"].(float64)
	if !ok {
		return "", fmt.Errorf("ID not found or invalid type")
	}
	return fmt.Sprintf("%d", int(id)), nil
}
