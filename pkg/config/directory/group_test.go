package directory_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type GroupTestSuite struct {
	suite.Suite

	ctx         context.Context
	vctx        *contextx.VerifyContext
	groupName   string
	client      *directory.GroupClient
	groupCreate directory.Group
	groupPatch  directory.GroupPatchRequest
}

func (s *GroupTestSuite) SetupTest() {
	var err error
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// load common config
	tenant, accessToken := test_helper.LoadCommonConfig(s.T())

	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = accessToken
	s.vctx.Tenant = tenant

	// load specific config
	s.groupName = "Admins"

	// group details for creation
	groupCreateRawData := `
displayName: Admins
members:
- action: add
  type: user
  value: testUser
schemas:
- urn:ietf:params:scim:schemas:core:2.0:Group
- urn:ietf:params:scim:schemas:extension:ibm:2.0:Group
- urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification
urn:ietf:params:scim:schemas:extension:ibm:2.0:Group:
  description: Administrators Group
visible: true
`
	_ = yaml.Unmarshal([]byte(groupCreateRawData), &s.groupCreate)

	groupPatchRawData := `
displayName: Admins
scimPatch:
  Operations:
  - op: add
    path: members
    value:
    - type: user
      value: testUser1
  - op: remove
    path: members[value eq "testUser"]
`
	_ = yaml.Unmarshal([]byte(groupPatchRawData), &s.groupPatch)

	s.client = directory.NewGroupClient()
}

func (s *GroupTestSuite) TestGetGroup() {
	var err error
	// Create group
	_, err = s.client.CreateGroup(s.ctx, &s.groupCreate)
	require.NoError(s.T(), err, "unable to create a group %s; err=%v", s.groupName, err)

	// Get group details
	_, _, err = s.client.GetGroupByName(s.ctx, s.groupName)
	require.NoError(s.T(), err, "unable to get group %s; err=%v", s.groupName, err)

	// Get group list
	_, _, err = s.client.GetGroups(s.ctx, "", "", "")
	require.NoError(s.T(), err, "unable to list groups; err=%v", err)

	// Update group
	err = s.client.UpdateGroup(s.ctx, s.groupName, &s.groupPatch.SCIMPatchRequest.Operations)
	require.NoError(s.T(), err, "unable to update group %s; err=%v", s.groupName, err)

	// Delete group
	err = s.client.DeleteGroup(s.ctx, s.groupName)
	require.NoError(s.T(), err, "unable to delete group %s; err=%v", s.groupName, err)
}

func TestGroupTestSuite(t *testing.T) {
	suite.Run(t, new(GroupTestSuite))
}
