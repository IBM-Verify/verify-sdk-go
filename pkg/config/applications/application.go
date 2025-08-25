package applications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type ApplicationListResponse = openapi.SearchAdminApplicationWithoutProvResponseBean

type Embedded struct {
	Applications []*Application `json:"applications" yaml:"applications"`
}

type Application struct {
	Name                   string                 `json:"name" yaml:"name"`
	TemplateID             string                 `json:"templateId" yaml:"templateId"`
	Links                  Links                  `json:"_links" yaml:"_links,omitempty"`
	Providers              Providers              `json:"providers" yaml:"providers"`
	Provisioning           Provisioning           `json:"provisioning" yaml:"provisioning"`
	AttributeMappings      []*AttributeMapping    `json:"attributeMappings" yaml:"attributeMappings"`
	ApplicationState       bool                   `json:"applicationState" yaml:"applicationState,omitempty"`
	ApprovalRequired       bool                   `json:"approvalRequired" yaml:"approvalRequired,omitempty"`
	SignonState            bool                   `json:"signonState" yaml:"signonState,omitempty"`
	Description            string                 `json:"description" yaml:"description,omitempty"`
	ProvisioningMode       string                 `json:"provisioningMode" yaml:"provisioningMode,omitempty"`
	IdentitySources        []string               `json:"identitySources" yaml:"identitySources,omitempty"`
	VisibleOnLaunchpad     bool                   `json:"visibleOnLaunchpad" yaml:"visibleOnLaunchpad,omitempty"`
	Customization          Customization          `json:"customization" yaml:"customization,omitempty"`
	DevportalSettings      DevportalSettings      `json:"devportalSettings" yaml:"devportalSettings,omitempty"`
	APIAccessClients       []*APIAccessClient     `json:"apiAccessClients" yaml:"apiAccessClients"`
	CustomIcon             string                 `json:"customIcon" yaml:"customIcon,omitempty"`
	AdaptiveAuthentication AdaptiveAuthentication `json:"adaptiveAuthentication" yaml:"adaptiveAuthentication,omitempty"`
	Target                 map[string]bool        `json:"target" yaml:"target,omitempty"`
	Owners                 []any                  `json:"owners,omitempty" yaml:"owners,omitempty"`
}
type Customization struct {
	ThemeID string `json:"themeId" yaml:"themeId,omitempty"`
}
type AdaptiveAuthentication struct {
	Platform    string `json:"platform" yaml:"platform,omitempty"`
	LicenseData string `json:"licenseData" yaml:"licenseData,omitempty"`
	StorageLink string `json:"storageLink" yaml:"storageLink,omitempty"`
}
type DevportalSettings struct {
	GrantTypes                 GrantTypes          `json:"grantTypes" yaml:"grantTypes,omitempty"`
	AuthPolicy                 AuthPolicy          `json:"authPolicy" yaml:"authPolicy,omitempty"`
	ExtendedProperties         map[string]string   `json:"extendedProperties" yaml:"extendedProperties,omitempty"`
	IdentitySources            []string            `json:"identitySources" yaml:"identitySources,omitempty"`
	SendAllKnownUserAttributes string              `json:"sendAllKnownUserAttributes" yaml:"sendAllKnownUserAttributes,omitempty"`
	AttributeMappings          []*AttributeMapping `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
}
type AuthPolicy struct {
	ID               string            `json:"id" yaml:"id,omitempty"`
	Name             string            `json:"name" yaml:"name,omitempty"`
	GrantTypes       []*GrantTypeEntry `json:"grantTypes" yaml:"grantTypes,omitempty"`
	ErrorCode        string            `json:"errorCode" yaml:"errorCode,omitempty"`
	ErrorDescription string            `json:"errorDescription" yaml:"errorDescription,omitempty"`
}
type GrantTypeEntry struct {
	Name  string `json:"name" yaml:"name,omitempty"`
	Value bool   `json:"value" yaml:"value,omitempty"`
}

type Links struct {
	Self Self `json:"self" yaml:"self,omitempty"`
}

type Self struct {
	Href string `json:"href" yaml:"href,omitempty"`
}

type Providers struct {
	SSO      SSO      `json:"sso" yaml:"sso,omitempty"`
	SAML     SAML     `json:"saml" yaml:"saml,omitempty"`
	Bookmark Bookmark `json:"bookmark" yaml:"bookmark,omitempty"`
	OIDC     OIDC     `json:"oidc" yaml:"oidc,omitempty"`
	WSFed    WSFed    `json:"wsfed" yaml:"wsfed,omitempty"`
}

type SSO struct {
	DomainName             string `json:"domainName" yaml:"domainName,omitempty"`
	UserOptions            string `json:"userOptions" yaml:"userOptions,omitempty"`
	SPSSOURL               string `json:"spssoUrl" yaml:"spssoUrl,omitempty"`
	TargetURL              string `json:"targetUrl" yaml:"targetUrl,omitempty"`
	IDPInitiatedSSOSupport string `json:"idpInitiatedSSOSupport" yaml:"idpInitiatedSSOSupport,omitempty"`
}

type SAML struct {
	JustInTimeProvisioning   string              `json:"justInTimeProvisioning" yaml:"justInTimeProvisioning,omitempty"`
	Properties               SAMLProperties      `json:"properties" yaml:"properties,omitempty"`
	AssertionConsumerService []any               `json:"assertionConsumerService" yaml:"assertionConsumerService,omitempty"`
	SingleLogoutService      []any               `json:"singleLogoutService" yaml:"singleLogoutService,omitempty"`
	AdditionalProperties     []any               `json:"additionalProperties" yaml:"additionalProperties,omitempty"`
	ManageNameIDService      ManageNameIDService `json:"manageNameIDService" yaml:"manageNameIDService,omitempty"`
}

type SAMLProperties struct {
	CompanyName                      string `json:"companyName" yaml:"companyName,omitempty"`
	GenerateUniqueID                 string `json:"generateUniqueID" yaml:"generateUniqueID,omitempty"`
	SignAuthnResponse                string `json:"signAuthnResponse" yaml:"signAuthnResponse,omitempty"`
	SignatureAlgorithm               string `json:"signatureAlgorithm" yaml:"signatureAlgorithm,omitempty"`
	ValidateAuthnRequest             string `json:"validateAuthnRequest" yaml:"validateAuthnRequest,omitempty"`
	EncryptAssertion                 string `json:"encryptAssertion" yaml:"encryptAssertion,omitempty"`
	ICIReservedSubjectNameID         string `json:"ici_reserved_subjectNameID" yaml:"ici_reserved_subjectNameID,omitempty"`
	IncludeAllAttributes             string `json:"includeAllAttributes" yaml:"includeAllAttributes,omitempty"`
	DefaultNameIdFormat              string `json:"defaultNameIdFormat" yaml:"defaultNameIdFormat,omitempty"`
	ProviderID                       string `json:"providerId" yaml:"providerId,omitempty"`
	AssertionConsumerServiceURL      string `json:"assertionConsumerServiceUrl" yaml:"assertionConsumerServiceUrl,omitempty"`
	SignatureValidationKeyIdentifier string `json:"signatureValidationKeyIdentifier" yaml:"signatureValidationKeyIdentifier,omitempty"`
	BlockEncryptionAlgorithm         string `json:"blockEncryptionAlgorithm" yaml:"blockEncryptionAlgorithm,omitempty"`
	EncryptionKeyIdentifier          string `json:"encryptionKeyIdentifier" yaml:"encryptionKeyIdentifier,omitempty"`
	UniqueID                         string `json:"uniqueID" yaml:"uniqueID,omitempty"`
	SessionNotOnOrAfter              string `json:"sessionNotOnOrAfter" yaml:"sessionNotOnOrAfter,omitempty"`
	SigningKeyIdentifier             string `json:"signingKeyIdentifier" yaml:"signingKeyIdentifier,omitempty"`
	ValidateLogoutRequest            string `json:"validateLogoutRequest" yaml:"validateLogoutRequest,omitempty"`
	ValidateLogoutResponse           string `json:"validateLogoutResponse" yaml:"validateLogoutResponse,omitempty"`
	UseMetaData                      string `json:"useMetaData" yaml:"useMetaData,omitempty"`
}

type ManageNameIDService struct {
	URL string `json:"url" yaml:"url"`
}

type Bookmark struct {
	BookmarkURL string `json:"bookmarkUrl" yaml:"bookmarkUrl,omitempty"`
}

type OIDC struct {
	Properties              OIDCProperties      `json:"properties" yaml:"properties,omitempty"`
	GrantProperties         GrantProperties     `json:"grantProperties" yaml:"grantProperties,omitempty"`
	Token                   Token               `json:"token" yaml:"token,omitempty"`
	JWTBearerProperties     JWTBearerProperties `json:"jwtBearerProperties" yaml:"jwtBearerProperties,omitempty"`
	ApplicationURL          string              `json:"applicationUrl" yaml:"applicationUrl,omitempty"`
	RestrictScopes          string              `json:"restrictScopes" yaml:"restrictScopes,omitempty"`
	Scopes                  []any               `json:"scopes" yaml:"scopes,omitempty"`
	Entitlements            []any               `json:"entitlements" yaml:"entitlements,omitempty"`
	RestrictEntitlements    bool                `json:"restrictEntitlements" yaml:"restrictEntitlements,omitempty"`
	ConsentAction           string              `json:"consentAction" yaml:"consentAction,omitempty"`
	RequirePKCEVerification string              `json:"requirePkceVerification" yaml:"requirePkceVerification,omitempty"`
}

type OIDCProperties struct {
	GrantTypes                 GrantTypes           `json:"grantTypes" yaml:"grantTypes,omitempty"`
	RedirectURIs               []any                `json:"redirectUris" yaml:"redirectUris,omitempty"`
	IDTokenSigningAlg          string               `json:"idTokenSigningAlg" yaml:"idTokenSigningAlg,omitempty"`
	AccessTokenExpiry          int                  `json:"accessTokenExpiry" yaml:"accessTokenExpiry,omitempty"`
	RefreshTokenExpiry         int                  `json:"refreshTokenExpiry" yaml:"refreshTokenExpiry,omitempty"`
	DoNotGenerateClientSecret  string               `json:"doNotGenerateClientSecret" yaml:"doNotGenerateClientSecret,omitempty"`
	GenerateRefreshToken       string               `json:"generateRefreshToken" yaml:"generateRefreshToken,omitempty"`
	RenewRefreshTokenExpiry    int                  `json:"renewRefreshTokenExpiry" yaml:"renewRefreshTokenExpiry,omitempty"`
	SignIDToken                string               `json:"signIdToken" yaml:"signIdToken,omitempty"`
	SigningCertificate         string               `json:"signingCertificate" yaml:"signingCertificate,omitempty"`
	ClientID                   string               `json:"clientId" yaml:"clientId,omitempty"`
	ClientSecret               string               `json:"clientSecret" yaml:"clientSecret,omitempty"`
	SendAllKnownUserAttributes string               `json:"sendAllKnownUserAttributes" yaml:"sendAllKnownUserAttributes,omitempty"`
	JWKSURI                    string               `json:"jwksUri" yaml:"jwksUri,omitempty"`
	ConsentType                string               `json:"consentType" yaml:"consentType,omitempty"`
	RenewRefreshToken          string               `json:"renewRefreshToken" yaml:"renewRefreshToken,omitempty"`
	IDTokenEncryptAlg          string               `json:"idTokenEncryptAlg" yaml:"idTokenEncryptAlg,omitempty"`
	IDTokenEncryptEnc          string               `json:"idTokenEncryptEnc" yaml:"idTokenEncryptEnc,omitempty"`
	IDTokenEncryptKey          string               `json:"idTokenEncryptKey" yaml:"idTokenEncryptKey,omitempty"`
	AdditionalConfig           OIDCAdditionalConfig `json:"additionalConfig" yaml:"additionalConfig,omitempty"`
}

type OIDCAdditionalConfig struct {
	Oidcv3                                 bool     `json:"oidcv3,omitempty" yaml:"oidcv3,omitempty"`
	RequestObjectParametersOnly            string   `json:"requestObjectParametersOnly,omitempty" yaml:"requestObjectParametersOnly,omitempty"`
	RequestObjectSigningAlg                string   `json:"requestObjectSigningAlg,omitempty" yaml:"requestObjectSigningAlg,omitempty"`
	RequestObjectRequireExp                string   `json:"requestObjectRequireExp,omitempty" yaml:"requestObjectRequireExp,omitempty"`
	CertificateBoundAccessTokens           string   `json:"certificateBoundAccessTokens,omitempty" yaml:"certificateBoundAccessTokens,omitempty"`
	DpopBoundAccessTokens                  string   `json:"dpopBoundAccessTokens,omitempty" yaml:"dpopBoundAccessTokens,omitempty"`
	ValidateDPoPProofJti                   string   `json:"validateDPoPProofJti,omitempty" yaml:"validateDPoPProofJti,omitempty"`
	DpopProofSigningAlg                    string   `json:"dpopProofSigningAlg,omitempty" yaml:"dpopProofSigningAlg,omitempty"`
	AuthorizeRspSigningAlg                 string   `json:"authorizeRspSigningAlg,omitempty" yaml:"authorizeRspSigningAlg,omitempty"`
	AuthorizeRspEncryptionAlg              string   `json:"authorizeRspEncryptionAlg,omitempty" yaml:"authorizeRspEncryptionAlg,omitempty"`
	AuthorizeRspEncryptionEnc              string   `json:"authorizeRspEncryptionEnc,omitempty" yaml:"authorizeRspEncryptionEnc,omitempty"`
	ResponseTypes                          []string `json:"responseTypes,omitempty" yaml:"responseTypes,omitempty"`
	ResponseModes                          []string `json:"responseModes,omitempty" yaml:"responseModes,omitempty"`
	ClientAuthMethod                       string   `json:"clientAuthMethod,omitempty" yaml:"clientAuthMethod,omitempty"`
	RequirePushAuthorize                   string   `json:"requirePushAuthorize,omitempty" yaml:"requirePushAuthorize,omitempty"`
	RequestObjectMaxExpFromNbf             int64    `json:"requestObjectMaxExpFromNbf,omitempty" yaml:"requestObjectMaxExpFromNbf,omitempty"`
	ExchangeForSSOSessionOption            string   `json:"exchangeForSSOSessionOption,omitempty" yaml:"exchangeForSSOSessionOption,omitempty"`
	SubjectTokenTypes                      []string `json:"subjectTokenTypes,omitempty" yaml:"subjectTokenTypes,omitempty"`
	ActorTokenTypes                        []string `json:"actorTokenTypes,omitempty" yaml:"actorTokenTypes,omitempty"`
	RequestedTokenTypes                    []string `json:"requestedTokenTypes,omitempty" yaml:"requestedTokenTypes,omitempty"`
	ActorTokenRequired                     bool     `json:"actorTokenRequired,omitempty" yaml:"actorTokenRequired,omitempty"`
	LogoutOption                           string   `json:"logoutOption,omitempty" yaml:"logoutOption,omitempty"`
	SessionRequired                        bool     `json:"sessionRequired,omitempty" yaml:"sessionRequired,omitempty"`
	RequestUris                            []string `json:"requestUris,omitempty" yaml:"requestUris,omitempty"`
	AllowedClientAssertionVerificationKeys []string `json:"allowedClientAssertionVerificationKeys,omitempty" yaml:"allowedClientAssertionVerificationKeys,omitempty"`
}

type GrantTypes struct {
	AuthorizationCode bool `json:"authorizationCode" yaml:"authorizationCode,omitempty"`
	Implicit          bool `json:"implicit" yaml:"implicit,omitempty"`
	DeviceFlow        bool `json:"deviceFlow" yaml:"deviceFlow,omitempty"`
	ROPC              bool `json:"ropc" yaml:"ropc,omitempty"`
	JWTBearer         bool `json:"jwtBearer" yaml:"jwtBearer,omitempty"`
	PolicyAuth        bool `json:"policyAuth" yaml:"policyAuth,omitempty"`
	ClientCredentials bool `json:"clientCredentials" yaml:"clientCredentials,omitempty"`
	TokenExchange     bool `json:"tokenExchange" yaml:"tokenExchange,omitempty"`
}

type GrantProperties struct {
	GenerateDeviceFlowQRCode string `json:"generateDeviceFlowQRCode" yaml:"generateDeviceFlowQRCode,omitempty"`
}

type Token struct {
	AccessTokenType   string `json:"accessTokenType" yaml:"accessTokenType"`
	Audiences         []any  `json:"audiences" yaml:"audiences,omitempty"`
	AttributeMappings []any  `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
}

type JWTBearerProperties struct {
	UserIdentifier string `json:"userIdentifier" yaml:"userIdentifier,omitempty"`
	IdentitySource string `json:"identitySource" yaml:"identitySource,omitempty"`
}
type Scopes struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description,omitempty"`
}
type WSFed struct {
	Properties WSFedProperties `json:"properties" yaml:"properties,omitempty"`
}

type WSFedProperties struct {
	ActiveProfile            ActiveProfile   `json:"activeProfile" yaml:"activeProfile,omitempty"`
	SigningSettings          SigningSettings `json:"signingSettings" yaml:"signingSettings,omitempty"`
	CallbackURL              string          `json:"callbackURL" yaml:"callbackURL,omitempty"`
	ProviderID               string          `json:"providerId" yaml:"providerId,omitempty"`
	MultipleDomainsEnabled   string          `json:"multipleDomainsEnabled" yaml:"multipleDomainsEnabled,omitempty"`
	ICIReservedSubjectNameID string          `json:"ici_reserved_subjectNameID" yaml:"ici_reserved_subjectNameID,omitempty"`
	AdditionalProperties     []any           `json:"additionalProperties" yaml:"additionalProperties,omitempty"`
}

type ActiveProfile struct {
	DefaultRealm string `json:"defaultRealm" yaml:"defaultRealm,omitempty"`
}

type SigningSettings struct {
	SignSAMLAssertion  string `json:"signSamlAssertion" yaml:"signSamlAssertion,omitempty"`
	KeyLabel           any    `json:"keyLabel" yaml:"keyLabel,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm" yaml:"signatureAlgorithm,omitempty"`
}

type Provisioning struct {
	Extension                Extension            `json:"extension" yaml:"extension,omitempty"`
	AttributeMappings        []*AttributeMapping  `json:"attributeMappings" yaml:"attributeMappings"`
	Policies                 ProvisioningPolicies `json:"policies" yaml:"policies,omitempty"`
	SendNotifications        bool                 `json:"sendNotifications" yaml:"sendNotifications,omitempty"`
	ReverseAttributeMappings []*AttributeMapping  `json:"reverseAttributeMappings" yaml:"reverseAttributeMappings"`
	Authentication           Authentication       `json:"authentication" yaml:"authentication,omitempty"`
	ProvisioningState        string               `json:"provisioningState" yaml:"provisioningState,omitempty"`
}

type Extension struct {
	Properties map[string]string `json:"properties" yaml:"properties,omitempty"`
}

type AttributeMapping struct {
	TargetName       string `json:"targetName" yaml:"targetName,omitempty"`
	SourceID         string `json:"sourceId" yaml:"sourceId,omitempty"`
	OutboundTracking bool   `json:"outboundTracking" yaml:"outboundTracking,omitempty"`
}

type ProvisioningPolicies struct {
	AdoptionPolicy AdoptionPolicy `json:"adoptionPolicy" yaml:"adoptionPolicy,omitempty"`
	ProvPolicy     string         `json:"provPolicy" yaml:"provPolicy,omitempty"`
	DeProvPolicy   string         `json:"deProvPolicy" yaml:"deProvPolicy,omitempty"`
	DeProvAction   string         `json:"deProvAction" yaml:"deProvAction,omitempty"`
	GracePeriod    int64          `json:"gracePeriod" yaml:"gracePeriod,omitempty"`
}

type AdoptionPolicy struct {
	MatchingAttributes []*AttributeMapping `json:"matchingAttributes" yaml:"matchingAttributes,omitempty"`
	RemediationPolicy  map[string]any      `json:"remediationPolicy,omitempty" yaml:"remediationPolicy,omitempty"`
}

type Authentication struct {
	Properties map[string]string `json:"properties" yaml:"properties,omitempty"`
}

type APIAccessClient struct {
	AccessTokenLifetime int32    `json:"accessTokenLifetime" yaml:"accessTokenLifetime,omitempty"`
	AccessTokenType     string   `json:"accessTokenType" yaml:"accessTokenType,omitempty"`
	ClientName          string   `json:"clientName" yaml:"clientName,omitempty"`
	ClientID            string   `json:"clientId" yaml:"clientId,omitempty"`
	Enabled             bool     `json:"enabled" yaml:"enabled,omitempty"`
	JWTSigningAlg       string   `json:"jwtSigningAlg" yaml:"jwtSigningAlg,omitempty"`
	SignKeyLabel        string   `json:"signKeyLabel" yaml:"signKeyLabel,omitempty"`
	RestrictScopes      bool     `json:"restrictScopes" yaml:"restrictScopes,omitempty"`
	IPFilterOp          string   `json:"ipFilterOp" yaml:"ipFilterOp,omitempty"`
	IPFilters           []string `json:"ipFilters" yaml:"ipFilters,omitempty"`
	JWKURI              string   `json:"jwkUri" yaml:"jwkUri,omitempty"`
	Scopes              []string `json:"scopes" yaml:"scopes,omitempty"`
	DefaultEntitlements []string `json:"defaultEntitlements" yaml:"defaultEntitlements,omitempty"`
}

type ApplicationClient struct {
	Client *http.Client
}

func NewApplicationClient() *ApplicationClient {
	return &ApplicationClient{
		Client: &http.Client{},
	}
}
func (c *ApplicationClient) CreateApplication(ctx context.Context, application *Application) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}
	body, err := json.Marshal(application)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal application data; err=%s", err.Error())
		return "", errorsx.G11NError("unable to marshal application data")
	}

	resp, err := client.CreateApplicationWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to create an Application; err=%s", err.Error())
		return "", errorsx.G11NError("unable to create application")
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create application"); err != nil {
			vc.Logger.Errorf("unable to create the application; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]any{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Errorf("Failed to unmarshal application response; err=%s", err.Error())
		return "", errorsx.G11NError("unable to parse response")
	}

	links, ok := m["_links"].(map[string]any)
	if !ok {
		vc.Logger.Errorf("Response missing _links field; body=%s", string(body))
		return "", errorsx.G11NError("missing _links field")
	}
	self, ok := links["self"].(map[string]any)
	if !ok {
		vc.Logger.Errorf("Response missing _links.self field; body=%s", string(body))
		return "", errorsx.G11NError("missing _links.self field")
	}
	href, ok := self["href"].(string)
	if !ok {
		vc.Logger.Errorf("Response missing _links.self.href field; body=%s", string(body))
		return "", errorsx.G11NError("missing _links.self.href")
	}

	id := strings.Split(href, "/")[len(strings.Split(href, "/"))-1]
	resourceURI := fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id)
	return resourceURI, nil
}

func (c *ApplicationClient) UpdateApplication(ctx context.Context, applicationID string, application *Application) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	if application == nil {
		vc.Logger.Errorf("application object is nil")
		return errorsx.G11NError("application object is nil")
	}

	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "*/*",
		Token:       vc.Token,
	}

	body, err := json.Marshal(application)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the Application; err=%s", err.Error())
		return errorsx.G11NError("unable to marshal the Application data")
	}

	resp, err := client.UpdateApplicationWithBodyWithResponse(ctx, applicationID, "*/*", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update an Application; err=%s", err.Error())
		return errorsx.G11NError("unable to update application")
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update application"); err != nil {
			vc.Logger.Errorf("unable to update the application; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to update application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *ApplicationClient) GetApplicationByID(ctx context.Context, applicationID string) (*Application, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetApplication(ctx, applicationID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Application; err=%s", err.Error())
		return nil, "", err
	}

	buf, err := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		vc.Logger.Errorf("unable to read the attributes body; err=%v", err)
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp, "unable to get application"); err != nil {
			vc.Logger.Errorf("unable to get the application; err=%s", err.Error())
			return nil, "", err
		}

		data, _ := io.ReadAll(resp.Body)
		vc.Logger.Errorf("unable to get the application; code=%d, body=%s", resp.StatusCode, string(data))
		return nil, "", errorsx.G11NError("unable to get the application")
	}

	app := &Application{}
	if err = json.Unmarshal(buf, app); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get Application")
	}

	return app, resp.Request.URL.String(), nil
}

func (c *ApplicationClient) GetApplications(ctx context.Context, search string, sort string, page int, limit int) (*ApplicationListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	params := &openapi.SearchApplicationsParams{}
	if len(search) > 0 {
		params.Search = &search
	}
	if len(sort) > 0 {
		params.Sort = &sort
	}
	if page > 0 {
		pageStr := strconv.Itoa(page)
		params.Page = &pageStr
	}
	if limit > 0 {
		limitStr := strconv.Itoa(limit)
		params.Limit = &limitStr
	}
	// u.RawQuery = q.Encode()

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.SearchApplicationsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get Applications; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Applications"); err != nil {
			vc.Logger.Errorf("unable to get the Applications; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to get the Applications")
		}

		vc.Logger.Errorf("unable to get the Applications; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the Applications")

	}

	applicationsResponse := &ApplicationListResponse{}
	if err = json.Unmarshal(resp.Body, applicationsResponse); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get the Applications")
	}

	return applicationsResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *ApplicationClient) DeleteApplicationByID(ctx context.Context, appliactionID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}

	resp, err := client.DeleteApplicationWithResponse(ctx, appliactionID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Application; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Application; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update application"); err != nil {
			vc.Logger.Errorf("unable to delete the application; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to delete application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to delete application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func ApplicationExample(applicationType string) *Application {
	var application *Application = &Application{}
	// setting common fields
	application.VisibleOnLaunchpad = true
	application.ApplicationState = true
	application.Description = " "
	application.TemplateID = " "
	if applicationType == "saml" {
		application.Owners = append(application.Owners, " ")
		// set target
		application.Target = map[string]bool{
			"connectedApp_SalesforceChatter":      true,
			"connectedApp_DataDotcom":             false,
			"connectedApp_SalesforceSalesCloud":   false,
			"connectedApp_SalesforceServiceCloud": false,
		}
		// set providers
		application.Providers = Providers{
			SAML: SAML{
				JustInTimeProvisioning: "false",
				Properties: SAMLProperties{
					CompanyName:                 " ",
					GenerateUniqueID:            "false",
					ValidateAuthnRequest:        "false",
					EncryptAssertion:            "false",
					ICIReservedSubjectNameID:    " ",
					IncludeAllAttributes:        "true",
					UniqueID:                    " ",
					ProviderID:                  " ",
					AssertionConsumerServiceURL: " ",
				},
			},
			SSO: SSO{
				DomainName:  " ",
				UserOptions: "saml",
			},
		}
		// set provisioning
		application.Provisioning = Provisioning{
			Policies: ProvisioningPolicies{
				GracePeriod:  1,
				ProvPolicy:   "disabled",
				DeProvPolicy: "disabled",
				DeProvAction: "suspend",
				AdoptionPolicy: AdoptionPolicy{
					MatchingAttributes: []*AttributeMapping{},
					RemediationPolicy: map[string]any{
						"policy": "NONE",
					},
				},
			},
		}
	} else if applicationType == "aclc" {
		// set provisioning
		application.Provisioning = Provisioning{
			Extension: Extension{
				Properties: map[string]string{
					"endpointBaseUrl": "",
				},
			},
			AttributeMappings: []*AttributeMapping{
				{TargetName: " ", SourceID: " ", OutboundTracking: true},
			},
			ReverseAttributeMappings: []*AttributeMapping{
				{TargetName: " ", SourceID: " ", OutboundTracking: true},
			},
			Policies: ProvisioningPolicies{
				ProvPolicy:   "automatic",
				DeProvPolicy: "automatic",
				DeProvAction: "delete",
				GracePeriod:  0,
				AdoptionPolicy: AdoptionPolicy{
					MatchingAttributes: []*AttributeMapping{
						{TargetName: " ", SourceID: " "},
					},
					RemediationPolicy: map[string]any{
						"policy": "NONE",
					},
				},
			},
			Authentication: Authentication{
				Properties: map[string]string{
					"pwd_client_secret": " ",
					"client_id":         " ",
				},
			},
			SendNotifications: true,
		}
		// set Provider
		application.Providers = Providers{
			SSO: SSO{
				DomainName:  " ",
				UserOptions: " ",
			},
			SAML: SAML{
				JustInTimeProvisioning: "false",
				Properties: SAMLProperties{
					CompanyName: " ",
				},
			},
			Bookmark: Bookmark{
				BookmarkURL: " ",
			},
		}
	} else if applicationType == "oidc" {
		// set providers
		application.Providers = Providers{
			SSO: SSO{
				UserOptions: "oidc",
			},
			SAML: SAML{
				Properties: SAMLProperties{
					CompanyName: " ",
					UniqueID:    " ",
				},
			},
			OIDC: OIDC{
				Properties: OIDCProperties{
					DoNotGenerateClientSecret: "false",
					GenerateRefreshToken:      "false",
					RenewRefreshToken:         "true",
					IDTokenEncryptAlg:         "none",
					IDTokenEncryptEnc:         "none",
					GrantTypes: GrantTypes{
						AuthorizationCode: true,
						Implicit:          true,
						ClientCredentials: true,
						ROPC:              true,
						TokenExchange:     true,
						DeviceFlow:        true,
						JWTBearer:         true,
						PolicyAuth:        true,
					},
					AccessTokenExpiry:  1,
					RefreshTokenExpiry: 1,
					IDTokenSigningAlg:  "RS256",
					RedirectURIs:       []interface{}{" ", " "},
					AdditionalConfig: OIDCAdditionalConfig{
						Oidcv3:                                 true,
						RequestObjectParametersOnly:            "false",
						RequestObjectSigningAlg:                "RS256",
						RequestObjectRequireExp:                "true",
						CertificateBoundAccessTokens:           "false",
						DpopBoundAccessTokens:                  "false",
						ValidateDPoPProofJti:                   "false",
						DpopProofSigningAlg:                    "RS256",
						AuthorizeRspSigningAlg:                 "RS256",
						AuthorizeRspEncryptionAlg:              "none",
						AuthorizeRspEncryptionEnc:              "none",
						ResponseTypes:                          []string{"none", "code"},
						ResponseModes:                          []string{"query", "fragment", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt"},
						ClientAuthMethod:                       "default",
						RequirePushAuthorize:                   "false",
						RequestObjectMaxExpFromNbf:             1,
						ExchangeForSSOSessionOption:            "default",
						SubjectTokenTypes:                      []string{"urn:ietf:params:oauth:token-type:access_token"},
						ActorTokenTypes:                        []string{"urn:ietf:params:oauth:token-type:access_token"},
						RequestedTokenTypes:                    []string{"urn:ietf:params:oauth:token-type:access_token"},
						ActorTokenRequired:                     true,
						LogoutOption:                           "none",
						SessionRequired:                        true,
						RequestUris:                            []string{" "},
						AllowedClientAssertionVerificationKeys: []string{" ", " "},
					},
				},
				Token: Token{
					AccessTokenType: "default",
					Audiences:       []interface{}{" "},
				},
				GrantProperties: GrantProperties{
					GenerateDeviceFlowQRCode: "false",
				},
				RequirePKCEVerification: "true",
				ConsentAction:           "always_promt",
				ApplicationURL:          " ",
				RestrictEntitlements:    true,
			},
		}

	} else if applicationType == "bookmark" {
		// set provisioning
		application.Provisioning = Provisioning{
			Policies: ProvisioningPolicies{
				GracePeriod:  1,
				ProvPolicy:   "disabled",
				DeProvPolicy: "disabled",
				DeProvAction: "delete",
				AdoptionPolicy: AdoptionPolicy{
					MatchingAttributes: []*AttributeMapping{},
					RemediationPolicy: map[string]any{
						"policy": "NONE",
					},
				},
			},
		}
		// set providers
		application.Providers = Providers{
			SAML: SAML{
				Properties: SAMLProperties{
					CompanyName: " ",
				},
			},
			SSO: SSO{
				UserOptions:            "applicationBookmark",
				IDPInitiatedSSOSupport: "false",
			},
			Bookmark: Bookmark{
				BookmarkURL: " ",
			},
		}
	}
	return application
}
