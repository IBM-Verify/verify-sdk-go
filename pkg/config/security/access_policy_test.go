package security_test

import (
	"context"
	"log/slog"
	"os"
	"strconv"
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

type AccessPolicyTestSuite struct {
	suite.Suite

	ctx                       context.Context
	vctx                      *contextx.VerifyContext
	accessPolicyName          string
	client                    *security.PolicyClient
	accessPolicyCreateOrPatch security.Policy
}

func (s *AccessPolicyTestSuite) SetupTest() {
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
	s.accessPolicyName = os.Getenv("ACCESS_POLICY_NAME")
	require.NotEmpty(s.T(), s.accessPolicyName, "invalid config: ACCESS_POLICY_NAME is missing")

	// Access Policy details for creation
	accessPolicyCreateRawData := `
name: TestPolicy
description: custom access policy
containsFirstFactor: true
rules:
  - name: My rule
    description: My rule
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: IN
            values:
              - US
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: My second rule 
    description: My second rule 
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: NOTIN
            values:
              - UK
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: test
    description: 'my test rule'
    alwaysRun: false
    firstFactor: false
    conditions:
    - opCode: MATCH
      values:
      - "127.0.0.2"
      type: ipAddress
    result:
      action: ACTION_MFA_ALWAYS
      serverSideActions: []
      authnMethods:
      - urn:ibm:security:authentication:asf:macotp
meta:
  state: ACTIVE
  schema: urn:access:policy:5.0:schema
  label: Initial revision
  scope:
    - "administrators"
  enforcementType: fedSSO
  evaluationContext: '{"landing":"12345665"}'
  tenantDefaultPolicy: false
validations:
  subscriptionsNeeded:
    - "string"
`

	_ = yaml.Unmarshal([]byte(accessPolicyCreateRawData), &s.accessPolicyCreateOrPatch)

	accessPolicyPatchRawData := `
name: TestPolicy
description: Updated TestPolicy
containsFirstFactor: true
rules:
  - name: My rule
    description: My rule
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: IN
            values:
              - US
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: My second rule 
    description: My second rule 
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: NOTIN
            values:
              - UK
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: test
    description: 'my test rule'
    alwaysRun: false
    firstFactor: false
    conditions:
    - opCode: MATCH
      values:
      - "127.0.0.2"
      type: ipAddress
    result:
      action: ACTION_MFA_ALWAYS
      serverSideActions: []
      authnMethods:
      - urn:ibm:security:authentication:asf:macotp
meta:
  state: ACTIVE
  schema: urn:access:policy:5.0:schema
  label: Initial revision
  scope:
    - "administrators"
  enforcementType: fedSSO
  evaluationContext: '{"landing":"12345665"}'
  tenantDefaultPolicy: false
validations:
  subscriptionsNeeded:
    - "string"
`
	_ = yaml.Unmarshal([]byte(accessPolicyPatchRawData), &s.accessPolicyCreateOrPatch)

	s.client = security.NewAccesspolicyClient()
}

func (s *AccessPolicyTestSuite) TestAccessPolicy() {
	var err error
	// Create Access Policy
	resp, err := s.client.CreateAccessPolicy(s.ctx, &s.accessPolicyCreateOrPatch)
	require.NoError(s.T(), err, "unable to create Access Policy %s; err=%v", s.accessPolicyName, err)
	// set the access policy ID
	policyID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Access Policy details
	_, _, err = s.client.GetAccesspolicy(s.ctx, s.accessPolicyName)
	require.NoError(s.T(), err, "unable to get Access Policy %s; err=%v", s.accessPolicyName, err)

	// Get Access Policy list
	_, _, err = s.client.GetAccesspolicies(s.ctx)
	require.NoError(s.T(), err, "unable to list Access Policies; err=%v", err)

	// Update Access Policy
	s.accessPolicyCreateOrPatch.ID, _ = strconv.Atoi(policyID)
	err = s.client.UpdateAccesspolicy(s.ctx, &s.accessPolicyCreateOrPatch)
	require.NoError(s.T(), err, "unable to update Access Policy %s; err=%v", s.accessPolicyName, err)

	// Delete Access Policy
	err = s.client.DeleteAccesspolicyByID(s.ctx, policyID)
	require.NoError(s.T(), err, "unable to delete Access Policy %s; err=%v", s.accessPolicyName, err)
}

func TestAccessPolicyTestSuite(t *testing.T) {
	suite.Run(t, new(AccessPolicyTestSuite))
}
