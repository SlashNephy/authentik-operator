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

package authentik

import (
	api "goauthentik.io/api/v3"
)

// The Diff functions build the body of a PATCH request from the desired state and the observed object
// (docs/spec.md §3.3).
//
// The desired state is expressed with the PATCH request type of the model: a field that is nil (or an unset
// Nullable) is not managed and is never sent. A managed field is sent only when its value differs from the
// observed object. List fields whose order is not stable on the server (property mappings, grant types, and
// redirect URIs) are compared as sets. The functions return nil and false when no managed field differs, so that
// the caller can skip the request.
//
// Fields that the server validates from the request body alone are always included in a non-nil result (§3.3):
// mode for Proxy Providers, and target plus the policy, group, or user field for PolicyBindings.

// DiffApplication returns the PATCH request for the Application fields of desired that differ from observed.
// Backchannel Providers are not managed and are ignored.
func DiffApplication(desired *api.PatchedApplicationRequest, observed *api.Application) (*api.PatchedApplicationRequest, bool) {
	patch := &api.PatchedApplicationRequest{
		Name:             diffValue(desired.Name, observed.Name),
		Slug:             diffValue(desired.Slug, observed.Slug),
		Provider:         diffNullableInt32(desired.Provider, observed.Provider),
		OpenInNewTab:     diffPointer(desired.OpenInNewTab, observed.OpenInNewTab),
		MetaLaunchUrl:    diffPointer(desired.MetaLaunchUrl, observed.MetaLaunchUrl),
		MetaIcon:         diffPointer(desired.MetaIcon, observed.MetaIcon),
		MetaDescription:  diffPointer(desired.MetaDescription, observed.MetaDescription),
		MetaPublisher:    diffPointer(desired.MetaPublisher, observed.MetaPublisher),
		PolicyEngineMode: diffPointer(desired.PolicyEngineMode, observed.PolicyEngineMode),
		Group:            diffPointer(desired.Group, observed.Group),
		MetaHide:         diffPointer(desired.MetaHide, observed.MetaHide),
	}
	changed := patch.Name != nil || patch.Slug != nil || patch.Provider.IsSet() || patch.OpenInNewTab != nil ||
		patch.MetaLaunchUrl != nil || patch.MetaIcon != nil || patch.MetaDescription != nil ||
		patch.MetaPublisher != nil || patch.PolicyEngineMode != nil || patch.Group != nil || patch.MetaHide != nil
	if !changed {
		return nil, false
	}
	return patch, true
}

// DiffProxyProvider returns the PATCH request for the Proxy Provider fields of desired that differ from observed.
// The result always carries mode, taken from desired or else from observed, because the server treats a missing
// mode as proxy. JWT federation settings are not managed and are ignored.
func DiffProxyProvider(desired *api.PatchedProxyProviderRequest, observed *api.ProxyProvider) (*api.PatchedProxyProviderRequest, bool) {
	patch := &api.PatchedProxyProviderRequest{
		Name:                       diffValue(desired.Name, observed.Name),
		AuthenticationFlow:         diffNullableString(desired.AuthenticationFlow, observed.AuthenticationFlow),
		AuthorizationFlow:          diffValue(desired.AuthorizationFlow, observed.AuthorizationFlow),
		InvalidationFlow:           diffValue(desired.InvalidationFlow, observed.InvalidationFlow),
		PropertyMappings:           diffSet(desired.PropertyMappings, observed.PropertyMappings),
		InternalHost:               diffPointer(desired.InternalHost, observed.InternalHost),
		ExternalHost:               diffValue(desired.ExternalHost, observed.ExternalHost),
		InternalHostSslValidation:  diffPointer(desired.InternalHostSslValidation, observed.InternalHostSslValidation),
		Certificate:                diffNullableString(desired.Certificate, observed.Certificate),
		SkipPathRegex:              diffPointer(desired.SkipPathRegex, observed.SkipPathRegex),
		BasicAuthEnabled:           diffPointer(desired.BasicAuthEnabled, observed.BasicAuthEnabled),
		BasicAuthPasswordAttribute: diffPointer(desired.BasicAuthPasswordAttribute, observed.BasicAuthPasswordAttribute),
		BasicAuthUserAttribute:     diffPointer(desired.BasicAuthUserAttribute, observed.BasicAuthUserAttribute),
		Mode:                       diffPointer(desired.Mode, observed.Mode),
		InterceptHeaderAuth:        diffPointer(desired.InterceptHeaderAuth, observed.InterceptHeaderAuth),
		CookieDomain:               diffPointer(desired.CookieDomain, observed.CookieDomain),
		AccessTokenValidity:        diffPointer(desired.AccessTokenValidity, observed.AccessTokenValidity),
		RefreshTokenValidity:       diffPointer(desired.RefreshTokenValidity, observed.RefreshTokenValidity),
	}
	changed := patch.Name != nil || patch.AuthenticationFlow.IsSet() || patch.AuthorizationFlow != nil ||
		patch.InvalidationFlow != nil || patch.PropertyMappings != nil || patch.InternalHost != nil ||
		patch.ExternalHost != nil || patch.InternalHostSslValidation != nil || patch.Certificate.IsSet() ||
		patch.SkipPathRegex != nil || patch.BasicAuthEnabled != nil || patch.BasicAuthPasswordAttribute != nil ||
		patch.BasicAuthUserAttribute != nil || patch.Mode != nil || patch.InterceptHeaderAuth != nil ||
		patch.CookieDomain != nil || patch.AccessTokenValidity != nil || patch.RefreshTokenValidity != nil
	if !changed {
		return nil, false
	}
	patch.Mode = firstNonNil(desired.Mode, observed.Mode)
	return patch, true
}

// DiffOAuth2Provider returns the PATCH request for the OAuth2 Provider fields of desired that differ from observed.
// JWT federation settings are not managed and are ignored.
func DiffOAuth2Provider(desired *api.PatchedOAuth2ProviderRequest, observed *api.OAuth2Provider) (*api.PatchedOAuth2ProviderRequest, bool) {
	patch := &api.PatchedOAuth2ProviderRequest{
		Name:                   diffValue(desired.Name, observed.Name),
		AuthenticationFlow:     diffNullableString(desired.AuthenticationFlow, observed.AuthenticationFlow),
		AuthorizationFlow:      diffValue(desired.AuthorizationFlow, observed.AuthorizationFlow),
		InvalidationFlow:       diffValue(desired.InvalidationFlow, observed.InvalidationFlow),
		PropertyMappings:       diffSet(desired.PropertyMappings, observed.PropertyMappings),
		ClientType:             diffPointer(desired.ClientType, observed.ClientType),
		GrantTypes:             diffSet(desired.GrantTypes, observed.GrantTypes),
		ClientId:               diffPointer(desired.ClientId, observed.ClientId),
		ClientSecret:           diffPointer(desired.ClientSecret, observed.ClientSecret),
		AccessCodeValidity:     diffPointer(desired.AccessCodeValidity, observed.AccessCodeValidity),
		AccessTokenValidity:    diffPointer(desired.AccessTokenValidity, observed.AccessTokenValidity),
		RefreshTokenValidity:   diffPointer(desired.RefreshTokenValidity, observed.RefreshTokenValidity),
		RefreshTokenThreshold:  diffPointer(desired.RefreshTokenThreshold, observed.RefreshTokenThreshold),
		IncludeClaimsInIdToken: diffPointer(desired.IncludeClaimsInIdToken, observed.IncludeClaimsInIdToken),
		SigningKey:             diffNullableString(desired.SigningKey, observed.SigningKey),
		EncryptionKey:          diffNullableString(desired.EncryptionKey, observed.EncryptionKey),
		RedirectUris:           diffRedirectURIs(desired.RedirectUris, observed.RedirectUris),
		LogoutUri:              diffPointer(desired.LogoutUri, observed.LogoutUri),
		LogoutMethod:           diffPointer(desired.LogoutMethod, observed.LogoutMethod),
		SubMode:                diffPointer(desired.SubMode, observed.SubMode),
		IssuerMode:             diffPointer(desired.IssuerMode, observed.IssuerMode),
	}
	changed := patch.Name != nil || patch.AuthenticationFlow.IsSet() || patch.AuthorizationFlow != nil ||
		patch.InvalidationFlow != nil || patch.PropertyMappings != nil || patch.ClientType != nil ||
		patch.GrantTypes != nil || patch.ClientId != nil || patch.ClientSecret != nil ||
		patch.AccessCodeValidity != nil || patch.AccessTokenValidity != nil || patch.RefreshTokenValidity != nil ||
		patch.RefreshTokenThreshold != nil || patch.IncludeClaimsInIdToken != nil || patch.SigningKey.IsSet() ||
		patch.EncryptionKey.IsSet() || patch.RedirectUris != nil || patch.LogoutUri != nil ||
		patch.LogoutMethod != nil || patch.SubMode != nil || patch.IssuerMode != nil
	if !changed {
		return nil, false
	}
	return patch, true
}

// DiffPolicyBinding returns the PATCH request for the PolicyBinding fields of desired that differ from observed.
// The result always carries target and the policy, group, or user field, taken from desired or else from
// observed, because the server validates them from the request body alone.
func DiffPolicyBinding(desired *api.PatchedPolicyBindingRequest, observed *api.PolicyBinding) (*api.PatchedPolicyBindingRequest, bool) {
	patch := &api.PatchedPolicyBindingRequest{
		Policy:        diffNullableString(desired.Policy, observed.Policy),
		Group:         diffNullableString(desired.Group, observed.Group),
		User:          diffNullableInt32(desired.User, observed.User),
		Target:        diffValue(desired.Target, observed.Target),
		Negate:        diffPointer(desired.Negate, observed.Negate),
		Enabled:       diffPointer(desired.Enabled, observed.Enabled),
		Order:         diffValue(desired.Order, observed.Order),
		Timeout:       diffPointer(desired.Timeout, observed.Timeout),
		FailureResult: diffPointer(desired.FailureResult, observed.FailureResult),
	}
	changed := patch.Policy.IsSet() || patch.Group.IsSet() || patch.User.IsSet() || patch.Target != nil ||
		patch.Negate != nil || patch.Enabled != nil || patch.Order != nil || patch.Timeout != nil ||
		patch.FailureResult != nil
	if !changed {
		return nil, false
	}

	patch.Target = firstNonNil(desired.Target, &observed.Target)
	if desired.Policy.IsSet() || desired.Group.IsSet() || desired.User.IsSet() {
		patch.Policy, patch.Group, patch.User = desired.Policy, desired.Group, desired.User
	} else {
		patch.Policy, patch.Group, patch.User = observed.Policy, observed.Group, observed.User
	}
	return patch, true
}

// diffValue returns desired when it is set and differs from the observed value.
func diffValue[T comparable](desired *T, observed T) *T {
	if desired == nil || *desired == observed {
		return nil
	}
	return desired
}

// diffPointer returns desired when it is set and differs from the observed value. An unset observed value
// differs from every desired value.
func diffPointer[T comparable](desired, observed *T) *T {
	if desired == nil || (observed != nil && *desired == *observed) {
		return nil
	}
	return desired
}

// diffNullableString returns desired when it is set and its value (possibly null) differs from the observed value.
func diffNullableString(desired, observed api.NullableString) api.NullableString {
	if !desired.IsSet() || equalPointers(desired.Get(), observed.Get()) {
		return api.NullableString{}
	}
	return desired
}

// diffNullableInt32 returns desired when it is set and its value (possibly null) differs from the observed value.
func diffNullableInt32(desired, observed api.NullableInt32) api.NullableInt32 {
	if !desired.IsSet() || equalPointers(desired.Get(), observed.Get()) {
		return api.NullableInt32{}
	}
	return desired
}

func equalPointers[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// diffSet returns desired when it is non-nil and does not contain the same distinct elements as observed.
// A non-nil empty desired slice is managed and means "no elements".
func diffSet[T comparable](desired, observed []T) []T {
	if desired == nil || sameSet(desired, observed) {
		return nil
	}
	return desired
}

// sameSet reports whether both slices contain the same distinct elements, ignoring order and duplicates.
func sameSet[T comparable](a, b []T) bool {
	want := make(map[T]struct{}, len(a))
	for _, v := range a {
		want[v] = struct{}{}
	}
	have := make(map[T]struct{}, len(b))
	for _, v := range b {
		if _, ok := want[v]; !ok {
			return false
		}
		have[v] = struct{}{}
	}
	return len(want) == len(have)
}

// redirectURIKey identifies a redirect URI. A missing type is the server default, authorization.
type redirectURIKey struct {
	url          string
	matchingMode api.MatchingModeEnum
	uriType      api.RedirectURITypeEnum
}

func redirectURIType(t *api.RedirectURITypeEnum) api.RedirectURITypeEnum {
	if t == nil {
		return api.REDIRECTURITYPEENUM_AUTHORIZATION
	}
	return *t
}

// diffRedirectURIs compares redirect URIs as sets of (url, matching mode, type).
func diffRedirectURIs(desired []api.RedirectURIRequest, observed []api.RedirectURI) []api.RedirectURIRequest {
	if desired == nil {
		return nil
	}
	want := make([]redirectURIKey, 0, len(desired))
	for _, d := range desired {
		want = append(want, redirectURIKey{url: d.Url, matchingMode: d.MatchingMode, uriType: redirectURIType(d.RedirectUriType)})
	}
	have := make([]redirectURIKey, 0, len(observed))
	for _, o := range observed {
		have = append(have, redirectURIKey{url: o.Url, matchingMode: o.MatchingMode, uriType: redirectURIType(o.RedirectUriType)})
	}
	if sameSet(want, have) {
		return nil
	}
	return desired
}

func firstNonNil[T any](values ...*T) *T {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}
