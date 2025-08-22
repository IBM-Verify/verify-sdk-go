package directory

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

type UserClient struct {
	Client *http.Client
}

type User = openapi.UserResponseV2
type UserListResponse = openapi.GetUsersResponseV2
type UserPatchOperation = openapi.PatchOperation0

type UserPatchRequest struct {
	UserName         string             `json:"userName" yaml:"userName"`
	SCIMPatchRequest *openapi.PatchBody `json:"scimPatch" yaml:"scimPatch"`
}

func NewUserClient() *UserClient {
	return &UserClient{}
}

func (c *UserClient) CreateUser(ctx context.Context, user *User) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to create user")
	body, err := json.Marshal(user)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal user data; err=%v", err)
		return "", defaultErr
	}
	var usershouldnotneedtoresetpassword openapi.CreateUserParamsUsershouldnotneedtoresetpassword = "false"
	params := &openapi.CreateUserParams{
		Usershouldnotneedtoresetpassword: &usershouldnotneedtoresetpassword,
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.CreateUserWithBodyWithResponse(ctx, params, "application/scim+json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("Unable to create user; err=%v", err)
		return "", defaultErr
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create user"); err != nil {
			vc.Logger.Errorf("unable to create the user; err=%s", err.Error())
			return "", errorsx.G11NError("unable to create the user; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("unable to create the user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]any{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return "", errorsx.G11NError("failed to parse response")
	}

	id := m["id"].(string)
	return fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id), nil
}

func (c *UserClient) GetUser(ctx context.Context, userName string) (*User, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	id, err := c.GetUserId(ctx, userName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	params := &openapi.GetUser0Params{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetUser0WithResponse(ctx, id, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the User; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get User"); err != nil {
			vc.Logger.Errorf("unable to get the User; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the User")
	}

	User := &User{}
	if err = json.Unmarshal(resp.Body, User); err != nil {
		return nil, "", errorsx.G11NError("unable to get the User")
	}

	return User, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *UserClient) GetUsers(ctx context.Context, sort string, count string) (*UserListResponse, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	params := &openapi.GetUsersParams{}
	if len(sort) > 0 {
		params.SortBy = &sort
	}
	if len(count) > 0 {
		params.Count = &count
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetUsersWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Users"); err != nil {
			vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Users; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Users")
	}

	UsersResponse := &UserListResponse{}
	if err = json.Unmarshal(resp.Body, &UsersResponse); err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s, body=%s", err, string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Users")
	}

	return UsersResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *UserClient) DeleteUser(ctx context.Context, name string) error {
	vc := contextx.GetVerifyContext(ctx)
	id, err := c.GetUserId(ctx, name)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return errorsx.G11NError("unable to get the user ID; err=%s", err.Error())
	}

	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}
	resp, err := client.DeleteUser0WithResponse(ctx, id, &openapi.DeleteUser0Params{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the User; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete User"); err != nil {
			vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the User; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("unable to delete the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *UserClient) UpdateUser(ctx context.Context, userName string, operations *[]UserPatchOperation) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	id, err := c.GetUserId(ctx, userName)
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return errorsx.G11NError("unable to get the user ID; err=%s", err.Error())
	}

	patchRequest := openapi.PatchBody{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: *operations,
	}

	body, err := json.Marshal(patchRequest)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return errorsx.G11NError("unable to marshal the patch request; err=%v", err)
	}
	var usershouldnotneedtoresetpassword openapi.PatchUserParamsUsershouldnotneedtoresetpassword = "false"
	params := &openapi.PatchUserParams{
		Usershouldnotneedtoresetpassword: &usershouldnotneedtoresetpassword,
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.PatchUserWithBodyWithResponse(ctx, id, params, "application/scim+json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to update user; err=%v", err)
		return errorsx.G11NError("unable to update user; err=%v", err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update user"); err != nil {
			vc.Logger.Errorf("unable to update the user; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("failed to update user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update user ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *UserClient) GetUserId(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	filter := fmt.Sprintf(`userName eq "%s"`, name)
	params := &openapi.GetUsersParams{
		Filter: &filter,
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	response, err := client.GetUsersWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the User with userName; err=%v", err)
		return "", errorsx.G11NError("unable to get the User with userName %s; err=%s", name, err.Error())
	}
	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get User"); err != nil {
			vc.Logger.Errorf("unable to get the User with userName %s; err=%s", name, err.Error())
			return "", errorsx.G11NError("unable to get the User with userName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]any
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", errorsx.G11NError("failed to parse response: %w", err)
	}

	resources, ok := data["Resources"].([]any)
	if !ok || len(resources) == 0 {
		return "", errorsx.G11NError("no user found with userName %s", name)
	}

	firstResource, ok := resources[0].(map[string]any)
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

func UserPatchExample() *openapi.PatchBody {
	patchBody := &openapi.PatchBody{
		Operations: []openapi.PatchOperation0{
			{
				Op:   openapi.PatchOperation0OpReplace,
				Path: "title",
			},
			{
				Op:   openapi.PatchOperation0OpAdd,
				Path: "emails",
			},
		},
	}
	var value1 interface{} = interface{}("Senior Engineer")
	patchBody.Operations[0].Value = (&value1)
	var value2 interface{} = interface{}(map[string]string{"type": "work", "value": "updated_email@work.com"})
	patchBody.Operations[1].Value = &value2

	return patchBody
}
