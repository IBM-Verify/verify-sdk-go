package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type GroupClient struct {
	Client *http.Client
}

type GroupPatchRequest struct {
	GroupName        string             `json:"displayName" yaml:"displayName"`
	SCIMPatchRequest *openapi.PatchBody `json:"scimPatch" yaml:"scimPatch"`
}

type Group = openapi.GroupResponseV2
type GroupListResponse = openapi.GetGroupsResponseV2
type GroupPatchOperation = openapi.PatchOperation0

var PathRegExp = regexp.MustCompile(`value eq "?([^"]+)"?`)

func NewGroupClient() *GroupClient {
	return &GroupClient{}
}

func (c *GroupClient) GetGroupByName(ctx context.Context, groupName string) (*Group, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	id, err := c.GetGroupId(ctx, groupName)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetGroupWithResponse(ctx, id, &openapi.GetGroupParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Group"); err != nil {
			vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Group")
	}

	Group := &Group{}
	if err = json.Unmarshal(resp.Body, Group); err != nil {
		return nil, "", errorsx.G11NError("unable to get the Group")
	}

	return Group, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *GroupClient) GetGroupByID(ctx context.Context, id string) (*Group, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetGroupWithResponse(ctx, id, &openapi.GetGroupParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Group"); err != nil {
			vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Group")
	}

	Group := &Group{}
	if err = json.Unmarshal(resp.Body, Group); err != nil {
		return nil, "", errorsx.G11NError("unable to get the Group")
	}

	return Group, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *GroupClient) GetGroups(ctx context.Context, sortBy string, sortOrder string, count string) (*GroupListResponse, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	params := &openapi.GetGroupsParams{}
	if len(sortBy) > 0 {
		params.SortBy = &sortBy
	}
	if len(sortOrder) > 0 {
		orderValue := openapi.GetGroupsParamsSortOrder(sortOrder)
		params.SortOrder = &orderValue
	}
	if len(count) > 0 {
		params.Count = &count
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetGroupsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to get the Groups; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Groups"); err != nil {
			vc.Logger.Errorf("unable to get the Groups; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Groups; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Groups")
	}

	GroupsResponse := &GroupListResponse{}
	if err = json.Unmarshal(resp.Body, &GroupsResponse); err != nil {
		vc.Logger.Errorf("unable to get the Groups; err=%s, body=%s", err, string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Groups")
	}

	return GroupsResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *GroupClient) CreateGroup(ctx context.Context, group *Group) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	userClient := NewUserClient()
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	if group.Members != nil {
		for i, m := range *group.Members {
			// Get the username from the member's Value field.
			username := m.Value
			// Retrieve the actual user ID using the provided function.
			userID, err := userClient.GetUserId(ctx, username)
			if err != nil {
				vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
				return "", errorsx.G11NError("unable to get user ID for username %s; err=%s", username, err.Error())
			}

			// Update the member's Value with the obtained user ID.
			(*group.Members)[i].Value = userID
		}
	}

	body, err := json.Marshal(group)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal group data; err=%v", err)
		return "", err
	}

	params := &openapi.CreateGroupParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.CreateGroupWithBodyWithResponse(ctx, params, "application/scim+json", bytes.NewBuffer(body), append(openapi.DefaultRequestEditors(ctx, headers), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("groupshouldnotneedtoresetpassword", "false")
		return nil
	})...)

	if err != nil {
		vc.Logger.Errorf("Unable to create group; err=%v", err)
		return "", err
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create group"); err != nil {
			vc.Logger.Errorf("unable to create the group; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]any{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return "", errorsx.G11NError("failed to parse response")
	}

	id := m["id"].(string)
	return fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id), nil
}

func (c *GroupClient) DeleteGroup(ctx context.Context, groupName string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	id, err := c.GetGroupId(ctx, groupName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return errorsx.G11NError("unable to get the group ID; err=%s", err.Error())
	}

	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}
	resp, err := client.DeleteGroupWithResponse(ctx, id, &openapi.DeleteGroupParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Group; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Group; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete Group"); err != nil {
			vc.Logger.Errorf("unable to delete the Group; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the Group; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the Group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("unable to delete the Group")
	}

	return nil
}

func (c *GroupClient) UpdateGroup(ctx context.Context, groupName string, operations *[]GroupPatchOperation) error {
	vc := contextx.GetVerifyContext(ctx)
	userClient := NewUserClient()
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	groupID, err := c.GetGroupId(ctx, groupName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return errorsx.G11NError("unable to get the group ID; err=%s", err.Error())
	}

	for i, op := range *operations {
		if op.Op == "add" && op.Path == "members" {
			if values, ok := (*op.Value).([]any); ok {
				for j, v := range values {
					if member, ok := v.(map[string]any); ok {
						if username, exists := member["value"].(string); exists {
							userID, err := userClient.GetUserId(ctx, username)
							if err != nil {
								vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
								return errorsx.G11NError("unable to get user ID for username %s; err=%s", username, err.Error())
							}
							(*(*operations)[i].Value).([]any)[j].(map[string]any)["value"] = userID
						}
					}
				}
			}
		} else if op.Op == "remove" {
			username := extractUsernameFromPath(op.Path)
			if username != "" {
				userID, err := userClient.GetUserId(ctx, username)
				if err != nil {
					vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
					return errorsx.G11NError("unable to get user ID for username %s; err=%s", username, err.Error())
				}
				(*operations)[i].Path = fmt.Sprintf("members[value eq \"%s\"]", userID)
			}
		}
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

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.PatchGroupWithBodyWithResponse(ctx, groupID, &openapi.PatchGroupParams{}, "application/scim+json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update group; err=%v", err)
		return errorsx.G11NError("unable to update group; err=%v", err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update group"); err != nil {
			vc.Logger.Errorf("unable to update the group; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("failed to update group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update group ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *GroupClient) GetGroupId(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	filter := fmt.Sprintf(`displayName eq "%s"`, name)
	params := &openapi.GetGroupsParams{
		Filter: &filter,
	}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/scim+json",
	}
	resp, err := client.GetGroupsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Group with groupName; err=%v", err)
		return "", errorsx.G11NError("unable to get the Group with groupName %s; err=%s", name, err.Error())
	}
	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Group"); err != nil {
			vc.Logger.Errorf("unable to get the Group with groupName %s; err=%s", name, err.Error())
			return "", errorsx.G11NError("unable to get the Group with groupName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]any
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return "", errorsx.G11NError("failed to parse response: %w", err)
	}

	resources, ok := data["Resources"].([]any)
	if !ok || len(resources) == 0 {
		return "", errorsx.G11NError("no group found with group name %s", name)
	}

	firstResource, ok := resources[0].(map[string]any)
	if !ok {
		return "", errorsx.G11NError("invalid resource format")
	}

	id, ok := firstResource["id"].(string)
	if !ok {
		return "", errorsx.G11NError("ID not found or invalid type")
	}

	return id, nil
}

func extractUsernameFromPath(path string) string {
	match := PathRegExp.FindStringSubmatch(path)

	if len(match) > 1 {
		return match[1]
	}
	return ""
}
