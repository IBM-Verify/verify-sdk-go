package integrations_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/auth"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/integrations"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IdentityAgentTestSuite struct {
	suite.Suite

	ctx                 context.Context
	vctx                *contextx.VerifyContext
	client              *integrations.IdentityAgentClient
	identityAgentCreate *integrations.IdentityAgentConfig
	identityAgentPatch  *integrations.IdentityAgentConfig
}

func (s *IdentityAgentTestSuite) SetupTest() {
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

	// Identity Agent details for creation
	identityAgentCreateRawData := `
apiClients: []
authnCacheTimeout: 0
certLabel: ""
description: "For provisioning"
heartbeat: 120
id: ""
modules: 
  - external:
      caCerts: ""
      id: "provuser"
      password: ""
      uri: 
        - "https://identity-brokerage:8443/BrokerageService/identity/broker"
name: "Provisioning agent"
purpose: "PROV"
references: []
`

	_ = yaml.Unmarshal([]byte(identityAgentCreateRawData), &s.identityAgentCreate)

	identityAgentPatchRawData := `
apiClients: []
authnCacheTimeout: 0
certLabel: ""
description: "For provisioning updated"
heartbeat: 120
modules: 
  - external:
      caCerts: ""
      id: "provuser"
      password: ""
      uri: 
        - "https://identity-brokerage:8443/BrokerageService/identity/broker"
name: "Provisioning agent"
purpose: "PROV"
references: []
`
	_ = yaml.Unmarshal([]byte(identityAgentPatchRawData), &s.identityAgentPatch)

	s.client = integrations.NewIdentityAgentClient()

}

func (s *IdentityAgentTestSuite) TestIdentityAgent() {
	var err error
	// Create Identity Agent
	resp, err := s.client.CreateIdentityAgent(s.ctx, s.identityAgentCreate)
	require.NoError(s.T(), err, "unable to create Identity Agent; err=%v", err)
	// set the Identity Agent ID
	identityAgentID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Identity Agent details
	_, _, err = s.client.GetIdentityAgentByID(s.ctx, identityAgentID)
	require.NoError(s.T(), err, "unable to get Identity Agent %s; err=%v", identityAgentID, err)

	// Get Identity Agent list
	_, _, err = s.client.GetIdentityAgents(s.ctx, "", 0, 0)
	require.NoError(s.T(), err, "unable to list Identity Agents; err=%v", err)

	// Update Identity Agent
	s.identityAgentPatch.ID = &identityAgentID
	err = s.client.UpdateIdentityAgent(s.ctx, s.identityAgentPatch)
	require.NoError(s.T(), err, "unable to update Identity Agent %s; err=%v", identityAgentID, err)

	// Delete Identity Agent
	err = s.client.DeleteIdentityAgentByID(s.ctx, identityAgentID)
	require.NoError(s.T(), err, "unable to delete Identity Agent %s; err=%v", identityAgentID, err)
}

func TestIdentityAgentTestSuite(t *testing.T) {
	suite.Run(t, new(IdentityAgentTestSuite))
}
