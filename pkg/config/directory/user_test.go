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

type UserTestSuite struct {
	suite.Suite

	ctx        context.Context
	vctx       *contextx.VerifyContext
	userName   string
	client     *directory.UserClient
	userCreate directory.User
	userPatch  directory.UserPatchRequest
}

func (s *UserTestSuite) SetupTest() {
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
	s.userName = "TestUserName"

	// user details for creation
	userCreateRawData := `
active: true
emails:
- type: work
  value: johndoe@work.com
name:
  familyName: Doe
  givenName: John
phoneNumbers:
- type: mobile
  value: '+1234567890'
schemas:
- urn:ietf:params:scim:schemas:core:2.0:User
- urn:ietf:params:scim:schemas:extension:ibm:2.0:User
- urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification
- urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
title: Engineer
urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:
  department: Engineering
  employeeNumber: '12345'
urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification:
  notifyManager: false
  notifyPassword: false
  notifyType: EMAIL
urn:ietf:params:scim:schemas:extension:ibm:2.0:User:
  userCategory: regular
userName: TestUserName
`

	_ = yaml.Unmarshal([]byte(userCreateRawData), &s.userCreate)

	userPatchRawData := `
scimPatch:
  Operations:
  - op: add
    path: title
    value: Senior Engineer
  - op: replace
    path: phoneNumbers
    value:
    - type: mobile
      value: "33333"
  - op: replace
    path: emails
    value:
    - type: work
      value: john.doe.updated@work.com
userName: TestUserName
`
	_ = yaml.Unmarshal([]byte(userPatchRawData), &s.userPatch)

	s.client = directory.NewUserClient()
}

func (s *UserTestSuite) TestGetUser() {
	var err error
	// Create user
	_, err = s.client.CreateUser(s.ctx, &s.userCreate)
	require.NoError(s.T(), err, "unable to create user %s; err=%v", s.userName, err)

	// Get user details
	_, _, err = s.client.GetUser(s.ctx, s.userName)
	require.NoError(s.T(), err, "unable to get user %s; err=%v", s.userName, err)

	// Get user list
	_, _, err = s.client.GetUsers(s.ctx, "", "", "")
	require.NoError(s.T(), err, "unable to list users; err=%v", err)

	// Update user
	err = s.client.UpdateUser(s.ctx, s.userName, &s.userPatch.SCIMPatchRequest.Operations)
	require.NoError(s.T(), err, "unable to update user %s; err=%v", s.userName, err)

	// Delete user
	err = s.client.DeleteUser(s.ctx, s.userName)
	require.NoError(s.T(), err, "unable to delete user %s; err=%v", s.userName, err)
}

func TestUserTestSuite(t *testing.T) {
	suite.Run(t, new(UserTestSuite))
}
