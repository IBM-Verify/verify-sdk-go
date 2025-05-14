package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"
	"gopkg.in/yaml.v2"
)

// type PasswordPolicy = openapi.PasswordPolicyResponseV3
// type PasswordPolicyListResponse = openapi.PasswordPoliciesResponseV3

type PasswordPolicyListResponse struct {
	TotalResults     int               `yaml:"totalResults" json:"totalResults"`
	Schemas          []string          `yaml:"schemas" json:"schemas"`
	PasswordPolicies []*PasswordPolicy `yaml:"Resources" json:"Resources"`
}

type PasswordPolicy struct {
	Schemas           []string         `yaml:"schemas" json:"schemas"`
	ID                string           `yaml:"id,omitempty" json:"id,omitempty"`
	PolicyName        string           `yaml:"policyName" json:"policyName"`
	PolicyDescription string           `yaml:"policyDescription,omitempty" json:"policyDescription,omitempty"`
	PasswordStrength  PasswordStrength `yaml:"passwordStrength,omitempty" json:"passwordStrength,omitempty"`
	PasswordSecurity  PasswordSecurity `yaml:"passwordSecurity,omitempty" json:"passwordSecurity,omitempty"`
}

type PasswordStrength struct {
	PwdMinLength                        int `yaml:"pwdMinLength,omitempty" json:"pwdMinLength,omitempty"`
	PasswordMaxConsecutiveRepeatedChars int `yaml:"passwordMaxConsecutiveRepeatedChars,omitempty" json:"passwordMaxConsecutiveRepeatedChars,omitempty"`
	PasswordMaxRepeatedChars            int `yaml:"passwordMaxRepeatedChars,omitempty" json:"passwordMaxRepeatedChars,omitempty"`
	PasswordMinAlphaChars               int `yaml:"passwordMinAlphaChars,omitempty" json:"passwordMinAlphaChars,omitempty"`
	PasswordMinDiffChars                int `yaml:"passwordMinDiffChars,omitempty" json:"passwordMinDiffChars,omitempty"`
	PasswordMinOtherChars               int `yaml:"passwordMinOtherChars,omitempty" json:"passwordMinOtherChars,omitempty"`
	PasswordMinLowerCaseChars           int `yaml:"passwordMinLowerCaseChars,omitempty" json:"passwordMinLowerCaseChars,omitempty"`
	PasswordMinUpperCaseChars           int `yaml:"passwordMinUpperCaseChars,omitempty" json:"passwordMinUpperCaseChars,omitempty"`
	PasswordMinNumberChars              int `yaml:"passwordMinNumberChars,omitempty" json:"passwordMinNumberChars,omitempty"`
	PasswordMinSpecialChars             int `yaml:"passwordMinSpecialChars,omitempty" json:"passwordMinSpecialChars,omitempty"`
}

type PasswordSecurity struct {
	IBM_pwdPolicy           bool `yaml:"ibm_pwdPolicy,omitempty" json:"ibm_pwdPolicy,omitempty"`
	PwdAllowUserChange      bool `yaml:"pwdAllowUserChange,omitempty" json:"pwdAllowUserChange,omitempty"`
	PwdCheckSyntax          int  `yaml:"pwdCheckSyntax,omitempty" json:"pwdCheckSyntax,omitempty"`
	PwdFailureCountInterval int  `yaml:"pwdFailureCountInterval,omitempty" json:"pwdFailureCountInterval,omitempty"`
	PwdGraceLoginLimit      int  `yaml:"pwdGraceLoginLimit,omitempty" json:"pwdGraceLoginLimit,omitempty"`
	PwdMinAge               int  `yaml:"pwdMinAge,omitempty" json:"pwdMinAge,omitempty"`
	PwdExpireWarning        int  `yaml:"pwdExpireWarning,omitempty" json:"pwdExpireWarning,omitempty"`
	PwdInHistory            int  `yaml:"pwdInHistory,omitempty" json:"pwdInHistory,omitempty"`
	PwdLockout              bool `yaml:"pwdLockout,omitempty" json:"pwdLockout,omitempty"`
	PwdLockoutDuration      int  `yaml:"pwdLockoutDuration,omitempty" json:"pwdLockoutDuration,omitempty"`
	PwdMaxAge               int  `yaml:"pwdMaxAge,omitempty" json:"pwdMaxAge,omitempty"`
	PwdMustChange           bool `yaml:"pwdMustChange,omitempty" json:"pwdMustChange,omitempty"`
	PwdMaxFailure           int  `yaml:"pwdMaxFailure,omitempty" json:"pwdMaxFailure,omitempty"`
	PwdSafeModify           bool `yaml:"pwdSafeModify,omitempty" json:"pwdSafeModify,omitempty"`
}

type PasswordPolicyClient struct {
	Client *http.Client
}

func NewPasswordPolicyClient() *PasswordPolicyClient {
	return &PasswordPolicyClient{}
}

func (c *PasswordPolicyClient) GetPasswordPolicyByID(ctx context.Context, passwordPolicyID string) (*PasswordPolicy, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}

	resp, err := client.GetPasswordPolicy0WithResponse(ctx, passwordPolicyID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the password policy; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get password policy"); err != nil {
			vc.Logger.Errorf("unable to get the password policy; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the password policy")
	}

	PasswordPolicy := &PasswordPolicy{}
	if err = json.Unmarshal(resp.Body, PasswordPolicy); err != nil {
		return nil, "", errorsx.G11NError("unable to get the Password Policy")
	}

	return PasswordPolicy, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *PasswordPolicyClient) CreatePasswordPolicy(ctx context.Context, PasswordPolicy *PasswordPolicy) (string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	defaultErr := errorsx.G11NError("unable to create password policy")

	headers := &openapi.Headers{
		Accept:      "application/scim+json",
		ContentType: "application/scim+json",
		Token:       vc.Token,
	}

	body, err := json.Marshal(PasswordPolicy)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the password policy; err=%v", err.Error())
		return "", defaultErr
	}

	resp, err := client.CreatePasswordPolicyWithBodyWithResponse(ctx, "application/scim+json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to create an password policy; err=%s", err.Error())
		return "", errorsx.G11NError("unable to create password policy")
	}
	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create password policy"); err != nil {
			vc.Logger.Errorf("unable to create the password policy; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]interface{}{}
	resourceURI := ""
	if err := yaml.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = resp.HTTPResponse.Header.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id)

	}
	return resourceURI, nil

}

func (c *PasswordPolicyClient) UpdatePasswordPolicy(ctx context.Context, passwordPolicy *PasswordPolicy) error {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Accept:      "application/scim+json",
		ContentType: "application/scim+json",
		Token:       vc.Token,
	}

	body, err := json.Marshal(passwordPolicy)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return errorsx.G11NError("unable to marshal the patch request; err=%v", err)
	}

	resp, err := client.PatchPasswordPolicyWithBodyWithResponse(ctx, passwordPolicy.ID, "application/scim+json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update an password policy; err=%s", err.Error())
		return errorsx.G11NError("unable to update password policy")
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update password policy"); err != nil {
			vc.Logger.Errorf("unable to update the password policy; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to update password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *PasswordPolicyClient) GetPasswordPolicies(ctx context.Context, sort string, count string) (*PasswordPolicyListResponse, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}

	resp, err := client.GetPasswordPoliciesWithResponse(ctx, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get password policies; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get password policies"); err != nil {
			vc.Logger.Errorf("unable to get the password policies; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to get the password policies")
		}

		vc.Logger.Errorf("unable to get the password policies; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the password policies")

	}

	PasswordPoliciesResponse := &PasswordPolicyListResponse{}
	if err = json.Unmarshal(resp.Body, &PasswordPoliciesResponse); err != nil {
		vc.Logger.Errorf("unable to get the Password Policies; err=%s, body=%s", err, string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Password Policies")
	}

	return PasswordPoliciesResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *PasswordPolicyClient) DeletePasswordPolicyByID(ctx context.Context, passwordPolicyID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}

	resp, err := client.DeletePasswordPolicyWithResponse(ctx, passwordPolicyID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the password policy; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the password policy; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update password policy"); err != nil {
			vc.Logger.Errorf("unable to delete the password policy; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to delete password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to delete password policy; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *PasswordPolicyClient) GetPasswordPolicyID(ctx context.Context, PolicyName string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}

	resp, err := client.GetPasswordPoliciesWithResponse(ctx, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the password policy with Name; err=%v", err)
		return "", errorsx.G11NError("unable to get the password policy with Name %s; err=%s", PolicyName, err.Error())
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get password policy"); err != nil {
			vc.Logger.Errorf("unable to get the password policy with Name %s; err=%s", PolicyName, err.Error())
			return "", errorsx.G11NError("unable to get the password policy with Name %s; err=%s", PolicyName, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return "", errorsx.G11NError("failed to parse response: %w", err)
	}

	resources, ok := data["Resources"].([]interface{})
	if !ok || len(resources) == 0 {
		return "", errorsx.G11NError("no Password Policy found with PolicyName %s", PolicyName)
	}

	for _, res := range resources {
		policy, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		if name, ok := policy["policyName"].(string); ok && name == PolicyName {
			if predefined, ok := policy["predefined"].(bool); ok && predefined {
				return "", errorsx.G11NError("cannot delete predefined policy '%s'", PolicyName)
			}

			if id, ok := policy["id"].(string); ok {
				return id, nil
			}

		}
	}

	return "", errorsx.G11NError("no valid non-predefined policy found with name: %s", PolicyName)
}
