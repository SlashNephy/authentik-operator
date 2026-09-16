/*
Copyright 2026 SlashNephy.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"cmp"
	"strings"

	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

// The desired functions translate the spec into PATCH request types of client-go. A nil or unset field is not
// managed (docs/spec.md §3.3). The create functions turn a desired state into a create request, filling the
// required fields and the defaults applied only on creation (docs/spec.md §2.3).

var policyEngineModes = map[v1alpha1.AccessMode]api.PolicyEngineMode{
	v1alpha1.AccessModeAny: api.POLICYENGINEMODE_ANY,
	v1alpha1.AccessModeAll: api.POLICYENGINEMODE_ALL,
}

var clientTypes = map[v1alpha1.ClientType]api.ClientTypeEnum{
	v1alpha1.ClientTypeConfidential: api.CLIENTTYPEENUM_CONFIDENTIAL,
	v1alpha1.ClientTypePublic:       api.CLIENTTYPEENUM_PUBLIC,
}

var grantTypes = map[v1alpha1.GrantType]api.GrantTypeEnum{
	v1alpha1.GrantTypeAuthorizationCode: api.GRANTTYPEENUM_AUTHORIZATION_CODE,
	v1alpha1.GrantTypeImplicit:          api.GRANTTYPEENUM_IMPLICIT,
	v1alpha1.GrantTypeHybrid:            api.GRANTTYPEENUM_HYBRID,
	v1alpha1.GrantTypeRefreshToken:      api.GRANTTYPEENUM_REFRESH_TOKEN,
	v1alpha1.GrantTypeClientCredentials: api.GRANTTYPEENUM_CLIENT_CREDENTIALS,
	v1alpha1.GrantTypePassword:          api.GRANTTYPEENUM_PASSWORD,
	v1alpha1.GrantTypeDeviceCode:        api.GRANTTYPEENUM_URN_IETF_PARAMS_OAUTH_GRANT_TYPE_DEVICE_CODE,
	v1alpha1.GrantTypeTokenExchange:     api.GRANTTYPEENUM_URN_IETF_PARAMS_OAUTH_GRANT_TYPE_TOKEN_EXCHANGE,
}

var subjectModes = map[v1alpha1.SubjectMode]api.SubModeEnum{
	v1alpha1.SubjectModeHashedUserID: api.SUBMODEENUM_HASHED_USER_ID,
	v1alpha1.SubjectModeUserID:       api.SUBMODEENUM_USER_ID,
	v1alpha1.SubjectModeUserUUID:     api.SUBMODEENUM_USER_UUID,
	v1alpha1.SubjectModeUserUsername: api.SUBMODEENUM_USER_USERNAME,
	v1alpha1.SubjectModeUserEmail:    api.SUBMODEENUM_USER_EMAIL,
	v1alpha1.SubjectModeUserUPN:      api.SUBMODEENUM_USER_UPN,
}

var issuerModes = map[v1alpha1.IssuerMode]api.IssuerModeEnum{
	v1alpha1.IssuerModeGlobal:      api.ISSUERMODEENUM_GLOBAL,
	v1alpha1.IssuerModePerProvider: api.ISSUERMODEENUM_PER_PROVIDER,
}

var logoutMethods = map[v1alpha1.LogoutMethod]api.OAuth2ProviderLogoutMethodEnum{
	v1alpha1.LogoutMethodBackChannel:  api.OAUTH2PROVIDERLOGOUTMETHODENUM_BACKCHANNEL,
	v1alpha1.LogoutMethodFrontChannel: api.OAUTH2PROVIDERLOGOUTMETHODENUM_FRONTCHANNEL,
}

var matchingModes = map[v1alpha1.MatchingMode]api.MatchingModeEnum{
	v1alpha1.MatchingModeStrict: api.MATCHINGMODEENUM_STRICT,
	v1alpha1.MatchingModeRegex:  api.MATCHINGMODEENUM_REGEX,
}

var redirectURITypes = map[v1alpha1.RedirectURIType]api.RedirectURITypeEnum{
	v1alpha1.RedirectURITypeAuthorization: api.REDIRECTURITYPEENUM_AUTHORIZATION,
	v1alpha1.RedirectURITypePostLogout:    api.REDIRECTURITYPEENUM_LOGOUT,
}

// mapEnum converts an optional spec enum. It returns nil when the value is unset.
func mapEnum[K comparable, V any](table map[K]V, value *K) *V {
	if value == nil {
		return nil
	}
	mapped := table[*value]
	return &mapped
}

// nullableString returns a set NullableString for a non-nil value and an unset one otherwise.
func nullableString(value *string) api.NullableString {
	if value == nil {
		return api.NullableString{}
	}
	return *api.NewNullableString(value)
}

// desiredApplication returns the managed fields of the Application. providerPK is nil when the spec has no
// provider, in which case the provider of the Application is not managed.
func desiredApplication(spec *v1alpha1.AuthentikApplicationSpec, providerPK *int32) *api.PatchedApplicationRequest {
	desired := &api.PatchedApplicationRequest{
		Name:             new(spec.Name),
		OpenInNewTab:     spec.OpenInNewTab,
		MetaLaunchUrl:    spec.LaunchURL,
		MetaIcon:         spec.Icon,
		MetaDescription:  spec.Description,
		MetaPublisher:    spec.Publisher,
		PolicyEngineMode: mapEnum(policyEngineModes, spec.Access.Mode),
		Group:            spec.Group,
		MetaHide:         spec.HideFromApplicationDashboard,
	}
	if providerPK != nil {
		desired.Provider = *api.NewNullableInt32(providerPK)
	}
	return desired
}

// createApplicationRequest returns the request that creates the Application with the desired fields.
func createApplicationRequest(slug string, desired *api.PatchedApplicationRequest) *api.ApplicationRequest {
	return &api.ApplicationRequest{
		Name:             *desired.Name,
		Slug:             slug,
		Provider:         desired.Provider,
		OpenInNewTab:     desired.OpenInNewTab,
		MetaLaunchUrl:    desired.MetaLaunchUrl,
		MetaIcon:         desired.MetaIcon,
		MetaDescription:  desired.MetaDescription,
		MetaPublisher:    desired.MetaPublisher,
		PolicyEngineMode: desired.PolicyEngineMode,
		Group:            desired.Group,
		MetaHide:         desired.MetaHide,
	}
}

// providerName returns the Provider name used on creation, which defaults to the slug.
func providerName(spec *v1alpha1.AuthentikApplicationSpec) string {
	if spec.Provider.Name != nil {
		return *spec.Provider.Name
	}
	return spec.Slug
}

// desiredProxyProvider returns the managed fields of the Proxy Provider. Scope mappings are not managed because
// the server overwrites them on every write (docs/spec.md §3.3).
func desiredProxyProvider(provider *v1alpha1.ProviderSpec, flows *reference.Flows, refs *reference.ProxyReferences) *api.PatchedProxyProviderRequest {
	proxy := provider.Proxy
	desired := &api.PatchedProxyProviderRequest{
		Name:                 provider.Name,
		AuthorizationFlow:    new(flows.Authorization),
		InvalidationFlow:     new(flows.Invalidation),
		AuthenticationFlow:   nullableString(flows.Authentication),
		Certificate:          nullableString(refs.Certificate),
		InterceptHeaderAuth:  proxy.InterceptHeaderAuth,
		AccessTokenValidity:  proxy.AccessTokenValidity,
		RefreshTokenValidity: proxy.RefreshTokenValidity,
	}
	switch {
	case proxy.Proxy != nil:
		desired.Mode = new(api.PROXYMODE_PROXY)
		desired.ExternalHost = new(proxy.Proxy.ExternalHost)
		desired.InternalHost = new(proxy.Proxy.InternalHost)
		desired.InternalHostSslValidation = proxy.Proxy.InternalHostSSLValidation
	case proxy.ForwardAuthSingle != nil:
		desired.Mode = new(api.PROXYMODE_FORWARD_SINGLE)
		desired.ExternalHost = new(proxy.ForwardAuthSingle.ExternalHost)
	case proxy.ForwardAuthDomain != nil:
		desired.Mode = new(api.PROXYMODE_FORWARD_DOMAIN)
		desired.ExternalHost = new(proxy.ForwardAuthDomain.AuthenticationURL)
		desired.CookieDomain = new(proxy.ForwardAuthDomain.CookieDomain)
	}
	if proxy.UnauthenticatedPaths != nil {
		desired.SkipPathRegex = new(strings.Join(proxy.UnauthenticatedPaths, "\n"))
	}
	if proxy.BasicAuth != nil {
		desired.BasicAuthEnabled = new(true)
		desired.BasicAuthUserAttribute = new(proxy.BasicAuth.UserAttribute)
		desired.BasicAuthPasswordAttribute = new(proxy.BasicAuth.PasswordAttribute)
	}
	return desired
}

// createProxyProviderRequest returns the request that creates the Proxy Provider with the desired fields.
func createProxyProviderRequest(name string, desired *api.PatchedProxyProviderRequest) *api.ProxyProviderRequest {
	return &api.ProxyProviderRequest{
		Name:                       name,
		AuthenticationFlow:         desired.AuthenticationFlow,
		AuthorizationFlow:          *desired.AuthorizationFlow,
		InvalidationFlow:           *desired.InvalidationFlow,
		InternalHost:               desired.InternalHost,
		ExternalHost:               *cmp.Or(desired.ExternalHost, new("")),
		InternalHostSslValidation:  desired.InternalHostSslValidation,
		Certificate:                desired.Certificate,
		SkipPathRegex:              desired.SkipPathRegex,
		BasicAuthEnabled:           desired.BasicAuthEnabled,
		BasicAuthPasswordAttribute: desired.BasicAuthPasswordAttribute,
		BasicAuthUserAttribute:     desired.BasicAuthUserAttribute,
		Mode:                       desired.Mode,
		InterceptHeaderAuth:        desired.InterceptHeaderAuth,
		CookieDomain:               desired.CookieDomain,
		AccessTokenValidity:        desired.AccessTokenValidity,
		RefreshTokenValidity:       desired.RefreshTokenValidity,
	}
}

// desiredOAuth2Provider returns the managed fields of the OAuth2 Provider. The client ID and the client secret
// come from the credentials (docs/spec.md §2.5).
func desiredOAuth2Provider(provider *v1alpha1.ProviderSpec, flows *reference.Flows, refs *reference.OAuth2References) *api.PatchedOAuth2ProviderRequest {
	oauth2 := provider.OAuth2
	desired := &api.PatchedOAuth2ProviderRequest{
		Name:                   provider.Name,
		AuthorizationFlow:      new(flows.Authorization),
		InvalidationFlow:       new(flows.Invalidation),
		AuthenticationFlow:     nullableString(flows.Authentication),
		PropertyMappings:       refs.Scopes,
		ClientType:             mapEnum(clientTypes, oauth2.ClientType),
		AccessCodeValidity:     oauth2.AccessCodeValidity,
		AccessTokenValidity:    oauth2.AccessTokenValidity,
		RefreshTokenValidity:   oauth2.RefreshTokenValidity,
		RefreshTokenThreshold:  oauth2.RefreshTokenThreshold,
		IncludeClaimsInIdToken: oauth2.IncludeClaimsInIDToken,
		SigningKey:             nullableString(refs.SigningKey),
		EncryptionKey:          nullableString(refs.EncryptionKey),
		LogoutUri:              oauth2.LogoutURI,
		LogoutMethod:           mapEnum(logoutMethods, oauth2.LogoutMethod),
		SubMode:                mapEnum(subjectModes, oauth2.SubjectMode),
		IssuerMode:             mapEnum(issuerModes, oauth2.IssuerMode),
	}
	if credentials := refs.Credentials; credentials != nil {
		// Without the Secret the client secret is not managed until the Secret is created from authentik's value.
		if credentials.ClientID != "" {
			desired.ClientId = new(credentials.ClientID)
		}
		if credentials.SecretExists {
			desired.ClientSecret = new(credentials.ClientSecret)
		}
	}
	if oauth2.GrantTypes != nil {
		desired.GrantTypes = make([]api.GrantTypeEnum, 0, len(oauth2.GrantTypes))
		for _, grantType := range oauth2.GrantTypes {
			desired.GrantTypes = append(desired.GrantTypes, grantTypes[grantType])
		}
	}
	if oauth2.RedirectURIs != nil {
		desired.RedirectUris = make([]api.RedirectURIRequest, 0, len(oauth2.RedirectURIs))
		for _, uri := range oauth2.RedirectURIs {
			desired.RedirectUris = append(desired.RedirectUris, api.RedirectURIRequest{
				Url:             uri.URL,
				MatchingMode:    *mapEnum(matchingModes, cmp.Or(uri.MatchingMode, new(v1alpha1.MatchingModeStrict))),
				RedirectUriType: mapEnum(redirectURITypes, cmp.Or(uri.Type, new(v1alpha1.RedirectURITypeAuthorization))),
			})
		}
	}
	return desired
}

// createOAuth2ProviderRequest returns the request that creates the OAuth2 Provider with the desired fields and the
// creation defaults.
func createOAuth2ProviderRequest(name string, desired *api.PatchedOAuth2ProviderRequest, defaults *reference.CreationDefaults) *api.OAuth2ProviderRequest {
	request := &api.OAuth2ProviderRequest{
		Name:                   name,
		AuthenticationFlow:     desired.AuthenticationFlow,
		AuthorizationFlow:      *desired.AuthorizationFlow,
		InvalidationFlow:       *desired.InvalidationFlow,
		PropertyMappings:       desired.PropertyMappings,
		ClientType:             desired.ClientType,
		GrantTypes:             desired.GrantTypes,
		ClientId:               desired.ClientId,
		ClientSecret:           desired.ClientSecret,
		AccessCodeValidity:     desired.AccessCodeValidity,
		AccessTokenValidity:    desired.AccessTokenValidity,
		RefreshTokenValidity:   desired.RefreshTokenValidity,
		RefreshTokenThreshold:  desired.RefreshTokenThreshold,
		IncludeClaimsInIdToken: desired.IncludeClaimsInIdToken,
		SigningKey:             desired.SigningKey,
		EncryptionKey:          desired.EncryptionKey,
		RedirectUris:           desired.RedirectUris,
		LogoutUri:              desired.LogoutUri,
		LogoutMethod:           desired.LogoutMethod,
		SubMode:                desired.SubMode,
		IssuerMode:             desired.IssuerMode,
	}
	if request.PropertyMappings == nil {
		request.PropertyMappings = defaults.Scopes
	}
	if !request.SigningKey.IsSet() && defaults.SigningKey != nil {
		request.SigningKey = *api.NewNullableString(defaults.SigningKey)
	}
	if request.RedirectUris == nil {
		// redirect_uris is required by the API, but an empty list is allowed.
		request.RedirectUris = []api.RedirectURIRequest{}
	}
	return request
}

// bindingSubject identifies the subject of a Binding: exactly one of group, user, and policy.
type bindingSubject struct {
	group  string
	user   int32
	policy string
}

func ruleSubject(rule *reference.Rule) bindingSubject {
	switch {
	case rule.Group != nil:
		return bindingSubject{group: *rule.Group}
	case rule.User != nil:
		return bindingSubject{user: *rule.User}
	default:
		return bindingSubject{policy: *rule.Policy}
	}
}

func observedSubject(binding *api.PolicyBinding) bindingSubject {
	switch {
	case binding.Group.Get() != nil && *binding.Group.Get() != "":
		return bindingSubject{group: *binding.Group.Get()}
	case binding.User.Get() != nil:
		return bindingSubject{user: *binding.User.Get()}
	case binding.Policy.Get() != nil:
		return bindingSubject{policy: *binding.Policy.Get()}
	}
	return bindingSubject{}
}

// desiredBinding returns the managed fields of the Binding of the rule on the target. order is not managed
// (docs/spec.md §2.4).
func desiredBinding(target string, rule *reference.Rule) *api.PatchedPolicyBindingRequest {
	desired := &api.PatchedPolicyBindingRequest{
		Target: new(target),
		Negate: new(rule.Negate),
	}
	switch {
	case rule.Group != nil:
		desired.Group = *api.NewNullableString(rule.Group)
	case rule.User != nil:
		desired.User = *api.NewNullableInt32(rule.User)
	default:
		desired.Policy = *api.NewNullableString(rule.Policy)
	}
	return desired
}

// createBindingRequest returns the request that creates the Binding with the desired fields.
func createBindingRequest(desired *api.PatchedPolicyBindingRequest, order int32) *api.PolicyBindingRequest {
	return &api.PolicyBindingRequest{
		Policy: desired.Policy,
		Group:  desired.Group,
		User:   desired.User,
		Target: *desired.Target,
		Negate: desired.Negate,
		Order:  order,
	}
}
