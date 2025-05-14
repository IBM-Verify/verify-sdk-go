package security_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/auth"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PasswordPolicyTestSuite struct {
	suite.Suite

	ctx                  context.Context
	vctx                 *contextx.VerifyContext
	PasswordPolicyName   string
	client               *security.PasswordPolicyClient
	passwordPolicyCreate security.PasswordPolicy
	passwordPolicyPatch  security.PasswordPolicy
}

func (s *PasswordPolicyTestSuite) SetupTest() {
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// load common config
	tenant, clientID, clientSecret := test_helper.LoadCommonConfig(s.T())

	// get token
	client := &auth.Client{
		Tenant: tenant,
		ClientAuth: &auth.ClientSecretPost{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}

	tokenResponse, err := client.TokenWithAPIClient(context.Background(), nil)
	require.NoError(s.T(), err, "unable to get a token; err=%v", err)

	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = tokenResponse.AccessToken
	s.vctx.Tenant = tenant

	// load specific config
	s.PasswordPolicyName = os.Getenv("PASSWORD_POLICY_NAME")
	require.NotEmpty(s.T(), s.PasswordPolicyName, "invalid config: PASSWORD_POLICY_NAME is missing")
	// Password Policy details for creation

	passwordPolicyCreateRawData := `
passwordSecurity:
  pwdExpireWarning: 0
  pwdInHistory: 5
  pwdLockout: true
  pwdLockoutDuration: 1800
  pwdMaxAge: 400
  pwdMaxFailure: 4
  pwdMinAge: 30
passwordStrength:
  passwordMaxConsecutiveRepeatedChars: 3
  passwordMaxRepeatedChars: 5
  passwordMinAlphaChars: 2
  passwordMinDiffChars: 3
  passwordMinLowerCaseChars: 1
  passwordMinNumberChars: 1
  passwordMinOtherChars: 2
  passwordMinSpecialChars: 1
  passwordMinUpperCaseChars: 1
  pwdMinLength: 10
policyName: MyCustomPolicy
policyDescription: "password policy description"
schemas:
- urn:ietf:params:scim:schemas:ibm:core:3.0:policy:Password
`

	_ = yaml.Unmarshal([]byte(passwordPolicyCreateRawData), &s.passwordPolicyCreate)

	passwordPolicyPatchRawData := `
passwordSecurity:
  pwdExpireWarning: 0
  pwdInHistory: 5
  pwdLockout: true
  pwdLockoutDuration: 1800
  pwdMaxAge: 400
  pwdMaxFailure: 4
  pwdMinAge: 30
passwordStrength:
  passwordMaxConsecutiveRepeatedChars: 3
  passwordMaxRepeatedChars: 5
  passwordMinAlphaChars: 2
  passwordMinDiffChars: 3
  passwordMinLowerCaseChars: 1
  passwordMinNumberChars: 1
  passwordMinOtherChars: 2
  passwordMinSpecialChars: 1
  passwordMinUpperCaseChars: 1
  pwdMinLength: 10
policyName: MyCustomPolicy
policyDescription: "updated password policy description"
schemas:
- urn:ietf:params:scim:schemas:ibm:core:3.0:policy:Password
`
	_ = yaml.Unmarshal([]byte(passwordPolicyPatchRawData), &s.passwordPolicyPatch)

	s.client = security.NewPasswordPolicyClient()
}

func (s *PasswordPolicyTestSuite) TestPasswordPolicy() {
	var err error
	// Create Password Policy
	resp, err := s.client.CreatePasswordPolicy(s.ctx, &s.passwordPolicyCreate)
	require.NoError(s.T(), err, "unable to create Password Policy %s; err=%v", s.PasswordPolicyName, err)
	// set the Password Policy ID
	passwordPolicyID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Password Policy details
	_, _, err = s.client.GetPasswordPolicyByID(s.ctx, passwordPolicyID)
	require.NoError(s.T(), err, "unable to get Password Policy %s; err=%v", passwordPolicyID, err)

	// Get Password Policy list
	_, _, err = s.client.GetPasswordPolicies(s.ctx, "", "")
	require.NoError(s.T(), err, "unable to list Password Policies; err=%v", err)

	// Update Password Policy
	s.passwordPolicyPatch.ID = passwordPolicyID
	err = s.client.UpdatePasswordPolicy(s.ctx, &s.passwordPolicyPatch)
	require.NoError(s.T(), err, "unable to update Password Policy %s; err=%v", passwordPolicyID, err)

	// Delete Password Policy
	err = s.client.DeletePasswordPolicyByID(s.ctx, passwordPolicyID)
	require.NoError(s.T(), err, "unable to delete Password Policy %s; err=%v", passwordPolicyID, err)
}

func TestPasswordPolicyTestSuite(t *testing.T) {
	suite.Run(t, new(PasswordPolicyTestSuite))
}
