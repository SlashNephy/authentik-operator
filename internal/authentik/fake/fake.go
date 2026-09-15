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

// Package fake provides an in-memory authentik.Client for unit tests.
//
// The fake reproduces the server behavior that the reconciler depends on and that was confirmed against
// authentik 2026.8 (docs/spec.md §7.1 and §8): unique Provider names across Provider types, unique client IDs,
// the one-to-one Application to Provider relation, the PATCH validation of Proxy Providers and PolicyBindings,
// the unfiltered owner lookup, and object permissions that outlive the object.
package fake

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

// Client is an in-memory authentik.Client. The zero value is not usable; create one with New.
type Client struct {
	mu sync.Mutex

	version  api.Version
	sequence int32

	applications      map[string]*api.Application // keyed by slug
	proxyProviders    map[int32]*api.ProxyProvider
	oauth2Providers   map[int32]*api.OAuth2Provider
	bindings          map[string]*api.PolicyBinding
	outposts          map[string]*api.Outpost
	roles             map[string]*api.Role
	objectPermissions []objectPermission
	groups            map[string]*api.Group
	users             map[int32]*api.User
	policies          map[string]*api.Policy
	flows             map[string]*api.Flow
	keyPairs          map[string]*api.CertificateKeyPair
	scopeMappings     map[string]*api.ScopeMapping
}

// objectPermission is a permission on one object assigned to a role.
type objectPermission struct {
	id         int32
	role       string
	model      api.ModelEnum
	objectPK   string
	permission string
}

var _ authentik.Client = new(Client)

// New returns an empty fake that reports authentik 2026.8.2.
func New() *Client {
	return &Client{
		version: api.Version{
			VersionCurrent:     "2026.8.2",
			VersionLatest:      "2026.8.2",
			VersionLatestValid: true,
		},
		applications:      map[string]*api.Application{},
		proxyProviders:    map[int32]*api.ProxyProvider{},
		oauth2Providers:   map[int32]*api.OAuth2Provider{},
		bindings:          map[string]*api.PolicyBinding{},
		outposts:          map[string]*api.Outpost{},
		roles:             map[string]*api.Role{},
		objectPermissions: []objectPermission{},
		groups:            map[string]*api.Group{},
		users:             map[int32]*api.User{},
		policies:          map[string]*api.Policy{},
		flows:             map[string]*api.Flow{},
		keyPairs:          map[string]*api.CertificateKeyPair{},
		scopeMappings:     map[string]*api.ScopeMapping{},
	}
}

// nextPK returns a new integer primary key. The caller must hold mu.
func (c *Client) nextPK() int32 {
	c.sequence++
	return c.sequence
}

// nextUUID returns a new UUID-shaped primary key. The caller must hold mu.
func (c *Client) nextUUID() string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", c.nextPK())
}

func copyOf[T any](v *T) *T {
	c := *v
	return &c
}

// cloneOrEmpty returns a copy of the slice, or an empty slice for nil.
func cloneOrEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return slices.Clone(s)
}

func notFound(operation, model string) error {
	return &authentik.APIError{
		Operation:  operation,
		StatusCode: http.StatusNotFound,
		Body:       fmt.Sprintf(`{"detail":"No %s matches the given query."}`, model),
	}
}

func badRequest(operation, field, message string) error {
	body, _ := json.Marshal(map[string][]string{field: {message}})
	return &authentik.APIError{Operation: operation, StatusCode: http.StatusBadRequest, Body: string(body)}
}

// SetVersion changes the version reported by GetVersion.
func (c *Client) SetVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version.VersionCurrent = version
}

// AddGroup stores a Group that references can resolve.
func (c *Client) AddGroup(name string) *api.Group {
	c.mu.Lock()
	defer c.mu.Unlock()
	group := &api.Group{Pk: c.nextUUID(), Name: name, Parents: []string{}, Users: []int32{}, Roles: []string{}, Children: []string{}}
	c.groups[group.Pk] = group
	return copyOf(group)
}

// AddUser stores a User that references can resolve.
func (c *Client) AddUser(username string) *api.User {
	c.mu.Lock()
	defer c.mu.Unlock()
	user := &api.User{Pk: c.nextPK(), Username: username, Name: username, Groups: []string{}, Roles: []string{}}
	c.users[user.Pk] = user
	return copyOf(user)
}

// AddPolicy stores a Policy that references can resolve.
func (c *Client) AddPolicy(name string) *api.Policy {
	c.mu.Lock()
	defer c.mu.Unlock()
	policy := &api.Policy{Pk: c.nextUUID(), Name: name}
	c.policies[policy.Pk] = policy
	return copyOf(policy)
}

// AddFlow stores a Flow that references can resolve.
func (c *Client) AddFlow(slug string) *api.Flow {
	c.mu.Lock()
	defer c.mu.Unlock()
	flow := &api.Flow{Pk: c.nextUUID(), Name: slug, Slug: slug, Title: slug}
	c.flows[flow.Pk] = flow
	return copyOf(flow)
}

// AddCertificateKeyPair stores a CertificateKeyPair that references can resolve.
func (c *Client) AddCertificateKeyPair(name string) *api.CertificateKeyPair {
	c.mu.Lock()
	defer c.mu.Unlock()
	keyPair := &api.CertificateKeyPair{Pk: c.nextUUID(), Name: name, PrivateKeyAvailable: true}
	c.keyPairs[keyPair.Pk] = keyPair
	return copyOf(keyPair)
}

// AddScopeMapping stores a ScopeMapping that references can resolve.
func (c *Client) AddScopeMapping(name, scopeName string) *api.ScopeMapping {
	c.mu.Lock()
	defer c.mu.Unlock()
	mapping := &api.ScopeMapping{Pk: c.nextUUID(), Name: name, ScopeName: scopeName}
	c.scopeMappings[mapping.Pk] = mapping
	return copyOf(mapping)
}

// AddOutpost stores an Outpost without Providers.
func (c *Client) AddOutpost(name string) *api.Outpost {
	c.mu.Lock()
	defer c.mu.Unlock()
	outpost := &api.Outpost{Pk: c.nextUUID(), Name: name, Providers: []int32{}}
	c.outposts[outpost.Pk] = outpost
	return c.copyOutpost(outpost)
}

func (c *Client) GetVersion(context.Context) (*api.Version, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return copyOf(&c.version), nil
}

// Applications

func (c *Client) GetApplication(_ context.Context, slug string) (*api.Application, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	app, ok := c.applications[slug]
	if !ok {
		return nil, notFound("GetApplication", "Application")
	}
	return copyOf(app), nil
}

// checkApplicationProvider enforces the one-to-one relation between Applications and Providers.
// The caller must hold mu.
func (c *Client) checkApplicationProvider(operation string, provider *int32, exceptSlug string) error {
	if provider == nil {
		return nil
	}
	if !c.providerExists(*provider) {
		return badRequest(operation, "provider", fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", *provider))
	}
	for slug, app := range c.applications {
		if slug != exceptSlug && app.Provider.IsSet() && app.Provider.Get() != nil && *app.Provider.Get() == *provider {
			return badRequest(operation, "provider", "application with this provider already exists.")
		}
	}
	return nil
}

func (c *Client) CreateApplication(_ context.Context, request *api.ApplicationRequest) (*api.Application, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "CreateApplication"

	if _, ok := c.applications[request.Slug]; ok {
		return nil, badRequest(operation, "slug", "application with this slug already exists.")
	}
	if err := c.checkApplicationProvider(operation, request.Provider.Get(), ""); err != nil {
		return nil, err
	}

	pk := c.nextUUID()
	app := &api.Application{
		Pk:                   pk,
		PbmUuid:              pk,
		Name:                 request.Name,
		Slug:                 request.Slug,
		Provider:             request.Provider,
		BackchannelProviders: []int32{},
		OpenInNewTab:         request.OpenInNewTab,
		MetaLaunchUrl:        request.MetaLaunchUrl,
		MetaIcon:             request.MetaIcon,
		MetaDescription:      request.MetaDescription,
		MetaPublisher:        request.MetaPublisher,
		PolicyEngineMode:     cmp.Or(request.PolicyEngineMode, new(api.POLICYENGINEMODE_ANY)),
		Group:                request.Group,
		MetaHide:             request.MetaHide,
	}
	c.applications[app.Slug] = app
	return copyOf(app), nil
}

func (c *Client) PatchApplication(_ context.Context, slug string, request *api.PatchedApplicationRequest) (*api.Application, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "PatchApplication"

	app, ok := c.applications[slug]
	if !ok {
		return nil, notFound(operation, "Application")
	}
	if request.Slug != nil && *request.Slug != slug {
		if _, taken := c.applications[*request.Slug]; taken {
			return nil, badRequest(operation, "slug", "application with this slug already exists.")
		}
	}
	if request.Provider.IsSet() {
		if err := c.checkApplicationProvider(operation, request.Provider.Get(), slug); err != nil {
			return nil, err
		}
		app.Provider = request.Provider
	}

	if request.Name != nil {
		app.Name = *request.Name
	}
	if request.OpenInNewTab != nil {
		app.OpenInNewTab = request.OpenInNewTab
	}
	if request.MetaLaunchUrl != nil {
		app.MetaLaunchUrl = request.MetaLaunchUrl
	}
	if request.MetaIcon != nil {
		app.MetaIcon = request.MetaIcon
	}
	if request.MetaDescription != nil {
		app.MetaDescription = request.MetaDescription
	}
	if request.MetaPublisher != nil {
		app.MetaPublisher = request.MetaPublisher
	}
	if request.PolicyEngineMode != nil {
		app.PolicyEngineMode = request.PolicyEngineMode
	}
	if request.Group != nil {
		app.Group = request.Group
	}
	if request.MetaHide != nil {
		app.MetaHide = request.MetaHide
	}
	if request.Slug != nil && *request.Slug != slug {
		delete(c.applications, slug)
		app.Slug = *request.Slug
		c.applications[app.Slug] = app
	}
	return copyOf(app), nil
}

// DeleteApplication deletes the Application and its Bindings. Object permissions on it are kept, as on the server.
func (c *Client) DeleteApplication(_ context.Context, slug string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	app, ok := c.applications[slug]
	if !ok {
		return notFound("DeleteApplication", "Application")
	}
	delete(c.applications, slug)
	for uuid, binding := range c.bindings {
		if binding.Target == app.PbmUuid {
			delete(c.bindings, uuid)
		}
	}
	return nil
}

// Providers

// providerExists reports whether a Provider of any type has the pk. The caller must hold mu.
func (c *Client) providerExists(pk int32) bool {
	_, proxy := c.proxyProviders[pk]
	_, oauth2 := c.oauth2Providers[pk]
	return proxy || oauth2
}

// providerNameTaken reports whether another Provider of any type has the name. The caller must hold mu.
func (c *Client) providerNameTaken(name string, exceptPK int32) bool {
	for pk, provider := range c.proxyProviders {
		if pk != exceptPK && provider.Name == name {
			return true
		}
	}
	for pk, provider := range c.oauth2Providers {
		if pk != exceptPK && provider.Name == name {
			return true
		}
	}
	return false
}

// assignedApplicationSlug returns the slug of the Application that uses the Provider. The caller must hold mu.
func (c *Client) assignedApplicationSlug(pk int32) api.NullableString {
	for slug, app := range c.applications {
		if app.Provider.IsSet() && app.Provider.Get() != nil && *app.Provider.Get() == pk {
			return *api.NewNullableString(new(slug))
		}
	}
	return *api.NewNullableString(nil)
}

// deleteProvider detaches a deleted Provider from Applications and Outposts. The caller must hold mu.
func (c *Client) deleteProvider(pk int32) {
	for _, app := range c.applications {
		if app.Provider.IsSet() && app.Provider.Get() != nil && *app.Provider.Get() == pk {
			app.Provider = *api.NewNullableInt32(nil)
		}
	}
	for _, outpost := range c.outposts {
		outpost.Providers = slices.DeleteFunc(outpost.Providers, func(p int32) bool { return p == pk })
	}
}

// checkProxyMode reproduces ProxyProviderSerializer.validate, which only looks at the request body:
// a missing mode is treated as proxy, and proxy requires internal_host.
func checkProxyMode(operation string, mode *api.ProxyMode, internalHost *string) error {
	if (mode == nil || *mode == api.PROXYMODE_PROXY) && (internalHost == nil || *internalHost == "") {
		return badRequest(operation, "internal_host", "Internal host cannot be empty when forward auth is disabled.")
	}
	return nil
}

func (c *Client) copyProxyProvider(provider *api.ProxyProvider) *api.ProxyProvider {
	out := copyOf(provider)
	out.AssignedApplicationSlug = c.assignedApplicationSlug(provider.Pk)
	return out
}

func (c *Client) GetProxyProvider(_ context.Context, pk int32) (*api.ProxyProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	provider, ok := c.proxyProviders[pk]
	if !ok {
		return nil, notFound("GetProxyProvider", "ProxyProvider")
	}
	return c.copyProxyProvider(provider), nil
}

func (c *Client) FindProxyProvidersByName(_ context.Context, name string) ([]api.ProxyProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	providers := []api.ProxyProvider{}
	for _, provider := range c.proxyProviders {
		if provider.Name == name {
			providers = append(providers, *c.copyProxyProvider(provider))
		}
	}
	return providers, nil
}

func (c *Client) CreateProxyProvider(_ context.Context, request *api.ProxyProviderRequest) (*api.ProxyProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "CreateProxyProvider"

	if err := checkProxyMode(operation, request.Mode, request.InternalHost); err != nil {
		return nil, err
	}
	if c.providerNameTaken(request.Name, 0) {
		return nil, badRequest(operation, "name", "provider with this name already exists.")
	}

	provider := &api.ProxyProvider{
		Pk:                         c.nextPK(),
		Name:                       request.Name,
		AuthenticationFlow:         request.AuthenticationFlow,
		AuthorizationFlow:          request.AuthorizationFlow,
		InvalidationFlow:           request.InvalidationFlow,
		PropertyMappings:           []string{},
		InternalHost:               request.InternalHost,
		ExternalHost:               request.ExternalHost,
		InternalHostSslValidation:  request.InternalHostSslValidation,
		Certificate:                request.Certificate,
		SkipPathRegex:              request.SkipPathRegex,
		BasicAuthEnabled:           request.BasicAuthEnabled,
		BasicAuthPasswordAttribute: request.BasicAuthPasswordAttribute,
		BasicAuthUserAttribute:     request.BasicAuthUserAttribute,
		Mode:                       cmp.Or(request.Mode, new(api.PROXYMODE_PROXY)),
		InterceptHeaderAuth:        request.InterceptHeaderAuth,
		RedirectUris:               []api.RedirectURI{},
		CookieDomain:               request.CookieDomain,
		JwtFederationSources:       []string{},
		JwtFederationProviders:     []int32{},
		AccessTokenValidity:        request.AccessTokenValidity,
		RefreshTokenValidity:       request.RefreshTokenValidity,
		OutpostSet:                 []string{},
	}
	c.proxyProviders[provider.Pk] = provider
	return c.copyProxyProvider(provider), nil
}

func (c *Client) PatchProxyProvider(_ context.Context, pk int32, request *api.PatchedProxyProviderRequest) (*api.ProxyProvider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "PatchProxyProvider"

	provider, ok := c.proxyProviders[pk]
	if !ok {
		return nil, notFound(operation, "ProxyProvider")
	}
	if err := checkProxyMode(operation, request.Mode, request.InternalHost); err != nil {
		return nil, err
	}
	if request.Name != nil && c.providerNameTaken(*request.Name, pk) {
		return nil, badRequest(operation, "name", "provider with this name already exists.")
	}

	if request.Name != nil {
		provider.Name = *request.Name
	}
	if request.AuthenticationFlow.IsSet() {
		provider.AuthenticationFlow = request.AuthenticationFlow
	}
	if request.AuthorizationFlow != nil {
		provider.AuthorizationFlow = *request.AuthorizationFlow
	}
	if request.InvalidationFlow != nil {
		provider.InvalidationFlow = *request.InvalidationFlow
	}
	if request.InternalHost != nil {
		provider.InternalHost = request.InternalHost
	}
	if request.ExternalHost != nil {
		provider.ExternalHost = *request.ExternalHost
	}
	if request.InternalHostSslValidation != nil {
		provider.InternalHostSslValidation = request.InternalHostSslValidation
	}
	if request.Certificate.IsSet() {
		provider.Certificate = request.Certificate
	}
	if request.SkipPathRegex != nil {
		provider.SkipPathRegex = request.SkipPathRegex
	}
	if request.BasicAuthEnabled != nil {
		provider.BasicAuthEnabled = request.BasicAuthEnabled
	}
	if request.BasicAuthPasswordAttribute != nil {
		provider.BasicAuthPasswordAttribute = request.BasicAuthPasswordAttribute
	}
	if request.BasicAuthUserAttribute != nil {
		provider.BasicAuthUserAttribute = request.BasicAuthUserAttribute
	}
	if request.Mode != nil {
		provider.Mode = request.Mode
	}
	if request.InterceptHeaderAuth != nil {
		provider.InterceptHeaderAuth = request.InterceptHeaderAuth
	}
	if request.CookieDomain != nil {
		provider.CookieDomain = request.CookieDomain
	}
	if request.AccessTokenValidity != nil {
		provider.AccessTokenValidity = request.AccessTokenValidity
	}
	if request.RefreshTokenValidity != nil {
		provider.RefreshTokenValidity = request.RefreshTokenValidity
	}
	return c.copyProxyProvider(provider), nil
}

func (c *Client) DeleteProxyProvider(_ context.Context, pk int32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.proxyProviders[pk]; !ok {
		return notFound("DeleteProxyProvider", "ProxyProvider")
	}
	delete(c.proxyProviders, pk)
	c.deleteProvider(pk)
	return nil
}

// clientIDTaken reports whether another OAuth2 Provider has the client ID. The caller must hold mu.
func (c *Client) clientIDTaken(clientID string, exceptPK int32) bool {
	for pk, provider := range c.oauth2Providers {
		if pk != exceptPK && provider.ClientId != nil && *provider.ClientId == clientID {
			return true
		}
	}
	return false
}

// randomString returns a random alphanumeric string, like the client ID and secret generated by authentik.
func randomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func toRedirectURIs(requests []api.RedirectURIRequest) []api.RedirectURI {
	uris := make([]api.RedirectURI, 0, len(requests))
	for _, request := range requests {
		uris = append(uris, api.RedirectURI{MatchingMode: request.MatchingMode, Url: request.Url, RedirectUriType: request.RedirectUriType})
	}
	return uris
}

func (c *Client) copyOAuth2Provider(provider *api.OAuth2Provider) *api.OAuth2Provider {
	out := copyOf(provider)
	out.AssignedApplicationSlug = c.assignedApplicationSlug(provider.Pk)
	return out
}

func (c *Client) GetOAuth2Provider(_ context.Context, pk int32) (*api.OAuth2Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	provider, ok := c.oauth2Providers[pk]
	if !ok {
		return nil, notFound("GetOAuth2Provider", "OAuth2Provider")
	}
	return c.copyOAuth2Provider(provider), nil
}

func (c *Client) FindOAuth2ProvidersByName(_ context.Context, name string) ([]api.OAuth2Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	providers := []api.OAuth2Provider{}
	for _, provider := range c.oauth2Providers {
		if provider.Name == name {
			providers = append(providers, *c.copyOAuth2Provider(provider))
		}
	}
	return providers, nil
}

func (c *Client) CreateOAuth2Provider(_ context.Context, request *api.OAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "CreateOAuth2Provider"

	if c.providerNameTaken(request.Name, 0) {
		return nil, badRequest(operation, "name", "provider with this name already exists.")
	}
	clientID := cmp.Or(request.ClientId, new(randomString(40)))
	if c.clientIDTaken(*clientID, 0) {
		return nil, badRequest(operation, "client_id", "o auth2 provider with this Client ID already exists.")
	}

	provider := &api.OAuth2Provider{
		Pk:                     c.nextPK(),
		Name:                   request.Name,
		AuthenticationFlow:     request.AuthenticationFlow,
		AuthorizationFlow:      request.AuthorizationFlow,
		InvalidationFlow:       request.InvalidationFlow,
		PropertyMappings:       cloneOrEmpty(request.PropertyMappings),
		ClientType:             request.ClientType,
		GrantTypes:             slices.Clone(request.GrantTypes),
		ClientId:               clientID,
		ClientSecret:           cmp.Or(request.ClientSecret, new(randomString(128))),
		AccessCodeValidity:     request.AccessCodeValidity,
		AccessTokenValidity:    request.AccessTokenValidity,
		RefreshTokenValidity:   request.RefreshTokenValidity,
		RefreshTokenThreshold:  request.RefreshTokenThreshold,
		IncludeClaimsInIdToken: request.IncludeClaimsInIdToken,
		SigningKey:             request.SigningKey,
		EncryptionKey:          request.EncryptionKey,
		RedirectUris:           toRedirectURIs(request.RedirectUris),
		LogoutUri:              request.LogoutUri,
		LogoutMethod:           request.LogoutMethod,
		SubMode:                request.SubMode,
		IssuerMode:             request.IssuerMode,
		JwtFederationSources:   []string{},
		JwtFederationProviders: []int32{},
	}
	c.oauth2Providers[provider.Pk] = provider
	return c.copyOAuth2Provider(provider), nil
}

func (c *Client) PatchOAuth2Provider(_ context.Context, pk int32, request *api.PatchedOAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "PatchOAuth2Provider"

	provider, ok := c.oauth2Providers[pk]
	if !ok {
		return nil, notFound(operation, "OAuth2Provider")
	}
	if request.Name != nil && c.providerNameTaken(*request.Name, pk) {
		return nil, badRequest(operation, "name", "provider with this name already exists.")
	}
	if request.ClientId != nil && c.clientIDTaken(*request.ClientId, pk) {
		return nil, badRequest(operation, "client_id", "o auth2 provider with this Client ID already exists.")
	}

	if request.Name != nil {
		provider.Name = *request.Name
	}
	if request.AuthenticationFlow.IsSet() {
		provider.AuthenticationFlow = request.AuthenticationFlow
	}
	if request.AuthorizationFlow != nil {
		provider.AuthorizationFlow = *request.AuthorizationFlow
	}
	if request.InvalidationFlow != nil {
		provider.InvalidationFlow = *request.InvalidationFlow
	}
	if request.PropertyMappings != nil {
		provider.PropertyMappings = slices.Clone(request.PropertyMappings)
	}
	if request.ClientType != nil {
		provider.ClientType = request.ClientType
	}
	if request.GrantTypes != nil {
		provider.GrantTypes = slices.Clone(request.GrantTypes)
	}
	if request.ClientId != nil {
		provider.ClientId = request.ClientId
	}
	if request.ClientSecret != nil {
		provider.ClientSecret = request.ClientSecret
	}
	if request.AccessCodeValidity != nil {
		provider.AccessCodeValidity = request.AccessCodeValidity
	}
	if request.AccessTokenValidity != nil {
		provider.AccessTokenValidity = request.AccessTokenValidity
	}
	if request.RefreshTokenValidity != nil {
		provider.RefreshTokenValidity = request.RefreshTokenValidity
	}
	if request.RefreshTokenThreshold != nil {
		provider.RefreshTokenThreshold = request.RefreshTokenThreshold
	}
	if request.IncludeClaimsInIdToken != nil {
		provider.IncludeClaimsInIdToken = request.IncludeClaimsInIdToken
	}
	if request.SigningKey.IsSet() {
		provider.SigningKey = request.SigningKey
	}
	if request.EncryptionKey.IsSet() {
		provider.EncryptionKey = request.EncryptionKey
	}
	if request.RedirectUris != nil {
		provider.RedirectUris = toRedirectURIs(request.RedirectUris)
	}
	if request.LogoutUri != nil {
		provider.LogoutUri = request.LogoutUri
	}
	if request.LogoutMethod != nil {
		provider.LogoutMethod = request.LogoutMethod
	}
	if request.SubMode != nil {
		provider.SubMode = request.SubMode
	}
	if request.IssuerMode != nil {
		provider.IssuerMode = request.IssuerMode
	}
	return c.copyOAuth2Provider(provider), nil
}

func (c *Client) DeleteOAuth2Provider(_ context.Context, pk int32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.oauth2Providers[pk]; !ok {
		return notFound("DeleteOAuth2Provider", "OAuth2Provider")
	}
	delete(c.oauth2Providers, pk)
	c.deleteProvider(pk)
	return nil
}

// PolicyBindings

func nullableStringSet(v api.NullableString) bool {
	return v.IsSet() && v.Get() != nil && *v.Get() != ""
}

func nullableInt32Set(v api.NullableInt32) bool {
	return v.IsSet() && v.Get() != nil
}

// checkBindingSubject reproduces PolicyBindingSerializer.validate: exactly one of policy, group, and user in the
// request body.
func checkBindingSubject(operation string, policy, group api.NullableString, user api.NullableInt32) error {
	count := 0
	for _, set := range []bool{nullableStringSet(policy), nullableStringSet(group), nullableInt32Set(user)} {
		if set {
			count++
		}
	}
	switch {
	case count > 1:
		return badRequest(operation, "non_field_errors", "Only one of 'group', 'policy', 'user' can be set.")
	case count < 1:
		return badRequest(operation, "non_field_errors", "One of 'group', 'policy', 'user' must be set.")
	}
	return nil
}

// bindingOrderTaken enforces the unique (policy, target, order) constraint. Like the database constraint, it
// does not apply to Bindings without a policy. The caller must hold mu.
func (c *Client) bindingOrderTaken(policy api.NullableString, target string, order int32, exceptUUID string) bool {
	if !nullableStringSet(policy) {
		return false
	}
	for uuid, binding := range c.bindings {
		if uuid != exceptUUID && nullableStringSet(binding.Policy) && *binding.Policy.Get() == *policy.Get() &&
			binding.Target == target && binding.Order == order {
			return true
		}
	}
	return false
}

func (c *Client) GetPolicyBinding(_ context.Context, uuid string) (*api.PolicyBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	binding, ok := c.bindings[uuid]
	if !ok {
		return nil, notFound("GetPolicyBinding", "PolicyBinding")
	}
	return copyOf(binding), nil
}

func (c *Client) ListPolicyBindings(_ context.Context, target string) ([]api.PolicyBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	bindings := []api.PolicyBinding{}
	for _, binding := range c.bindings {
		if binding.Target == target {
			bindings = append(bindings, *copyOf(binding))
		}
	}
	slices.SortFunc(bindings, func(a, b api.PolicyBinding) int { return cmp.Compare(a.Order, b.Order) })
	return bindings, nil
}

func (c *Client) CreatePolicyBinding(_ context.Context, request *api.PolicyBindingRequest) (*api.PolicyBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "CreatePolicyBinding"

	if err := checkBindingSubject(operation, request.Policy, request.Group, request.User); err != nil {
		return nil, err
	}
	if c.bindingOrderTaken(request.Policy, request.Target, request.Order, "") {
		return nil, badRequest(operation, "non_field_errors", "The fields policy, target, order must make a unique set.")
	}

	binding := &api.PolicyBinding{
		Pk:            c.nextUUID(),
		Policy:        request.Policy,
		Group:         request.Group,
		User:          request.User,
		Target:        request.Target,
		Negate:        cmp.Or(request.Negate, new(false)),
		Enabled:       cmp.Or(request.Enabled, new(true)),
		Order:         request.Order,
		Timeout:       cmp.Or(request.Timeout, new(int32(30))),
		FailureResult: cmp.Or(request.FailureResult, new(false)),
	}
	c.bindings[binding.Pk] = binding
	return copyOf(binding), nil
}

func (c *Client) PatchPolicyBinding(_ context.Context, uuid string, request *api.PatchedPolicyBindingRequest) (*api.PolicyBinding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "PatchPolicyBinding"

	binding, ok := c.bindings[uuid]
	if !ok {
		return nil, notFound(operation, "PolicyBinding")
	}
	if request.Target == nil {
		// The server dereferences the missing target and fails with an internal error.
		return nil, &authentik.APIError{Operation: operation, StatusCode: http.StatusInternalServerError, Body: "Internal Server Error"}
	}
	if err := checkBindingSubject(operation, request.Policy, request.Group, request.User); err != nil {
		return nil, err
	}
	// The serializer validates only the subject fields in the request, but a partial update keeps the stored
	// value of every omitted field, so a Binding can end up with more than one subject.
	policy, group, user := binding.Policy, binding.Group, binding.User
	if request.Policy.IsSet() {
		policy = request.Policy
	}
	if request.Group.IsSet() {
		group = request.Group
	}
	if request.User.IsSet() {
		user = request.User
	}
	order := binding.Order
	if request.Order != nil {
		order = *request.Order
	}
	if c.bindingOrderTaken(policy, *request.Target, order, uuid) {
		return nil, badRequest(operation, "non_field_errors", "The fields policy, target, order must make a unique set.")
	}

	binding.Target = *request.Target
	binding.Policy = policy
	binding.Group = group
	binding.User = user
	binding.Order = order
	if request.Negate != nil {
		binding.Negate = request.Negate
	}
	if request.Enabled != nil {
		binding.Enabled = request.Enabled
	}
	if request.Timeout != nil {
		binding.Timeout = request.Timeout
	}
	if request.FailureResult != nil {
		binding.FailureResult = request.FailureResult
	}
	return copyOf(binding), nil
}

func (c *Client) DeletePolicyBinding(_ context.Context, uuid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.bindings[uuid]; !ok {
		return notFound("DeletePolicyBinding", "PolicyBinding")
	}
	delete(c.bindings, uuid)
	return nil
}

// Outposts

func (c *Client) copyOutpost(outpost *api.Outpost) *api.Outpost {
	out := copyOf(outpost)
	out.Providers = slices.Clone(outpost.Providers)
	return out
}

func (c *Client) GetOutpost(_ context.Context, uuid string) (*api.Outpost, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	outpost, ok := c.outposts[uuid]
	if !ok {
		return nil, notFound("GetOutpost", "Outpost")
	}
	return c.copyOutpost(outpost), nil
}

func (c *Client) FindOutpostsByName(_ context.Context, name string) ([]api.Outpost, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	outposts := []api.Outpost{}
	for _, outpost := range c.outposts {
		if outpost.Name == name {
			outposts = append(outposts, *c.copyOutpost(outpost))
		}
	}
	return outposts, nil
}

func (c *Client) SetOutpostProviders(_ context.Context, uuid string, providers []int32) (*api.Outpost, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "SetOutpostProviders"

	outpost, ok := c.outposts[uuid]
	if !ok {
		return nil, notFound(operation, "Outpost")
	}
	for _, pk := range providers {
		if !c.providerExists(pk) {
			return nil, badRequest(operation, "providers", fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", pk))
		}
	}
	outpost.Providers = cloneOrEmpty(providers)
	return c.copyOutpost(outpost), nil
}

// RBAC

func (c *Client) GetRole(_ context.Context, uuid string) (*api.Role, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	role, ok := c.roles[uuid]
	if !ok {
		return nil, notFound("GetRole", "Role")
	}
	return copyOf(role), nil
}

func (c *Client) FindRolesByName(_ context.Context, name string) ([]api.Role, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	roles := []api.Role{}
	for _, role := range c.roles {
		if role.Name == name {
			roles = append(roles, *copyOf(role))
		}
	}
	return roles, nil
}

func (c *Client) CreateRole(_ context.Context, name string) (*api.Role, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, role := range c.roles {
		if role.Name == name {
			return nil, badRequest("CreateRole", "name", "role with this name already exists.")
		}
	}
	role := &api.Role{Pk: c.nextUUID(), Name: name}
	c.roles[role.Pk] = role
	return copyOf(role), nil
}

// DeleteRole deletes the role together with its object permissions, as the server does. It is not part of
// authentik.Client; tests use it to simulate the role being deleted in the UI (docs/spec.md §3.1).
func (c *Client) DeleteRole(uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.roles, uuid)
	c.objectPermissions = slices.DeleteFunc(c.objectPermissions, func(p objectPermission) bool { return p.role == uuid })
}

// objectExists reports whether the object of a supported model exists. The caller must hold mu.
func (c *Client) objectExists(model api.ModelEnum, objectPK string) bool {
	switch model {
	case api.MODELENUM_AUTHENTIK_CORE_APPLICATION:
		for _, app := range c.applications {
			if app.Pk == objectPK {
				return true
			}
		}
	case api.MODELENUM_AUTHENTIK_PROVIDERS_PROXY_PROXYPROVIDER, api.MODELENUM_AUTHENTIK_PROVIDERS_OAUTH2_OAUTH2PROVIDER:
		for pk := range c.proxyProviders {
			if fmt.Sprint(pk) == objectPK && model == api.MODELENUM_AUTHENTIK_PROVIDERS_PROXY_PROXYPROVIDER {
				return true
			}
		}
		for pk := range c.oauth2Providers {
			if fmt.Sprint(pk) == objectPK && model == api.MODELENUM_AUTHENTIK_PROVIDERS_OAUTH2_OAUTH2PROVIDER {
				return true
			}
		}
	case api.MODELENUM_AUTHENTIK_POLICIES_POLICYBINDING:
		_, ok := c.bindings[objectPK]
		return ok
	}
	return false
}

func (c *Client) AssignObjectPermission(_ context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	const operation = "AssignObjectPermission"

	if _, ok := c.roles[roleUUID]; !ok {
		return notFound(operation, "Role")
	}
	if !c.objectExists(model, objectPK) {
		return badRequest(operation, "object_pk", "Object does not exist.")
	}
	for _, p := range c.objectPermissions {
		if p.role == roleUUID && p.model == model && p.objectPK == objectPK && p.permission == permission {
			return nil
		}
	}
	c.objectPermissions = append(c.objectPermissions, objectPermission{
		id: c.nextPK(), role: roleUUID, model: model, objectPK: objectPK, permission: permission,
	})
	return nil
}

func (c *Client) UnassignObjectPermission(_ context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.roles[roleUUID]; !ok {
		return notFound("UnassignObjectPermission", "Role")
	}
	c.objectPermissions = slices.DeleteFunc(c.objectPermissions, func(p objectPermission) bool {
		return p.role == roleUUID && p.model == model && p.objectPK == objectPK && p.permission == permission
	})
	return nil
}

func (p objectPermission) toRoleObjectPermission() api.RoleObjectPermission {
	appLabel, codename, _ := strings.Cut(p.permission, ".")
	_, modelName, _ := strings.Cut(string(p.model), ".")
	return api.RoleObjectPermission{Id: p.id, Codename: codename, Model: modelName, AppLabel: appLabel, ObjectPk: p.objectPK, Name: codename}
}

func (c *Client) ListRoleObjectPermissions(_ context.Context, roleUUID string) ([]api.ExtraRoleObjectPermission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	permissions := []api.ExtraRoleObjectPermission{}
	for _, p := range c.objectPermissions {
		if p.role != roleUUID {
			continue
		}
		r := p.toRoleObjectPermission()
		permissions = append(permissions, api.ExtraRoleObjectPermission{
			Id: r.Id, Codename: r.Codename, Model: r.Model, AppLabel: r.AppLabel, ObjectPk: r.ObjectPk, Name: r.Name,
			AppLabelVerbose: r.AppLabel, ModelVerbose: r.Model,
		})
	}
	return permissions, nil
}

// ListObjectPermissionRoles returns the roles with a permission on the object. As on the server, the object
// permissions of each role are not narrowed to the object. Model-level permissions are not modeled by the fake.
func (c *Client) ListObjectPermissionRoles(_ context.Context, model api.ModelEnum, objectPK string) ([]api.RoleAssignedObjectPermission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	results := []api.RoleAssignedObjectPermission{}
	for uuid, role := range c.roles {
		holds := slices.ContainsFunc(c.objectPermissions, func(p objectPermission) bool {
			return p.role == uuid && p.model == model && p.objectPK == objectPK
		})
		if !holds {
			continue
		}
		permissions := []api.RoleObjectPermission{}
		for _, p := range c.objectPermissions {
			if p.role == uuid {
				permissions = append(permissions, p.toRoleObjectPermission())
			}
		}
		results = append(results, api.RoleAssignedObjectPermission{
			RolePk: uuid, Name: role.Name, ObjectPermissions: permissions, ModelPermissions: []api.RoleModelPermission{},
		})
	}
	return results, nil
}

// Lookups

func (c *Client) GetGroup(_ context.Context, uuid string) (*api.Group, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	group, ok := c.groups[uuid]
	if !ok {
		return nil, notFound("GetGroup", "Group")
	}
	return copyOf(group), nil
}

func (c *Client) FindGroupsByName(_ context.Context, name string) ([]api.Group, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.groups, func(group *api.Group) bool { return group.Name == name }), nil
}

func (c *Client) GetUser(_ context.Context, pk int32) (*api.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	user, ok := c.users[pk]
	if !ok {
		return nil, notFound("GetUser", "User")
	}
	return copyOf(user), nil
}

func (c *Client) FindUsersByUsername(_ context.Context, username string) ([]api.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.users, func(user *api.User) bool { return user.Username == username }), nil
}

func (c *Client) GetPolicy(_ context.Context, uuid string) (*api.Policy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	policy, ok := c.policies[uuid]
	if !ok {
		return nil, notFound("GetPolicy", "Policy")
	}
	return copyOf(policy), nil
}

func (c *Client) FindPoliciesByName(_ context.Context, name string) ([]api.Policy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.policies, func(policy *api.Policy) bool { return policy.Name == name }), nil
}

func (c *Client) GetFlow(_ context.Context, uuid string) (*api.Flow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	flow, ok := c.flows[uuid]
	if !ok {
		return nil, notFound("GetFlow", "Flow")
	}
	return copyOf(flow), nil
}

func (c *Client) FindFlowsBySlug(_ context.Context, slug string) ([]api.Flow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.flows, func(flow *api.Flow) bool { return flow.Slug == slug }), nil
}

func (c *Client) GetCertificateKeyPair(_ context.Context, uuid string) (*api.CertificateKeyPair, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keyPair, ok := c.keyPairs[uuid]
	if !ok {
		return nil, notFound("GetCertificateKeyPair", "CertificateKeyPair")
	}
	return copyOf(keyPair), nil
}

func (c *Client) FindCertificateKeyPairsByName(_ context.Context, name string) ([]api.CertificateKeyPair, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.keyPairs, func(keyPair *api.CertificateKeyPair) bool { return keyPair.Name == name }), nil
}

func (c *Client) GetScopeMapping(_ context.Context, uuid string) (*api.ScopeMapping, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mapping, ok := c.scopeMappings[uuid]
	if !ok {
		return nil, notFound("GetScopeMapping", "ScopeMapping")
	}
	return copyOf(mapping), nil
}

func (c *Client) FindScopeMappingsByScopeName(_ context.Context, scopeName string) ([]api.ScopeMapping, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return findAll(c.scopeMappings, func(mapping *api.ScopeMapping) bool { return mapping.ScopeName == scopeName }), nil
}

// findAll returns copies of the stored objects that match. The caller must hold mu.
func findAll[K comparable, T any](objects map[K]*T, keep func(*T) bool) []T {
	found := []T{}
	for _, object := range objects {
		if keep(object) {
			found = append(found, *copyOf(object))
		}
	}
	return found
}
