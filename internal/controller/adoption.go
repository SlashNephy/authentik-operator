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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

const (
	eventReasonAdopted = "Adopted"
	// redacted replaces confidential values in adoption diffs.
	redacted = "(redacted)"
)

// nameField is the name field of both the Application and the Providers in the API and in the spec.
const nameField = "name"

// confidentialFields are API fields whose values are never shown in adoption diffs (docs/spec.md §5).
var confidentialFields = []string{"client_secret"}

// applicationFieldPaths maps Application API fields to spec paths.
var applicationFieldPaths = map[string]string{
	nameField:            nameField,
	"meta_launch_url":    "launchURL",
	"meta_icon":          "icon",
	"meta_description":   "description",
	"meta_publisher":     "publisher",
	"group":              "group",
	"open_in_new_tab":    "openInNewTab",
	"meta_hide":          "hideFromApplicationDashboard",
	"policy_engine_mode": "access.mode",
}

// providerFieldPaths maps API fields shared by both Provider types to spec paths.
var providerFieldPaths = map[string]string{
	nameField:             "provider.name",
	"authorization_flow":  "provider.flows.authorization",
	"invalidation_flow":   "provider.flows.invalidation",
	"authentication_flow": "provider.flows.authentication",
}

// proxyFieldPaths maps Proxy Provider API fields to spec paths. external_host depends on the mode and is added by
// proxyFieldPathsFor.
var proxyFieldPaths = map[string]string{
	"mode":                          "provider.proxy",
	"internal_host":                 "provider.proxy.proxy.internalHost",
	"internal_host_ssl_validation":  "provider.proxy.proxy.internalHostSSLValidation",
	"cookie_domain":                 "provider.proxy.forwardAuthDomain.cookieDomain",
	"skip_path_regex":               "provider.proxy.unauthenticatedPaths",
	"basic_auth_enabled":            "provider.proxy.basicAuth",
	"basic_auth_user_attribute":     "provider.proxy.basicAuth.userAttribute",
	"basic_auth_password_attribute": "provider.proxy.basicAuth.passwordAttribute",
	"intercept_header_auth":         "provider.proxy.interceptHeaderAuth",
	"access_token_validity":         "provider.proxy.accessTokenValidity",
	"refresh_token_validity":        "provider.proxy.refreshTokenValidity",
	"certificate":                   "provider.proxy.certificate",
}

// oauth2FieldPaths maps OAuth2 Provider API fields to spec paths.
var oauth2FieldPaths = map[string]string{
	"property_mappings":          "provider.oauth2.scopes",
	"client_type":                "provider.oauth2.clientType",
	"grant_types":                "provider.oauth2.grantTypes",
	"client_id":                  "provider.oauth2.credentials.clientID",
	"client_secret":              "provider.oauth2.credentials.secretRef.clientSecretKey",
	"access_code_validity":       "provider.oauth2.accessCodeValidity",
	"access_token_validity":      "provider.oauth2.accessTokenValidity",
	"refresh_token_validity":     "provider.oauth2.refreshTokenValidity",
	"refresh_token_threshold":    "provider.oauth2.refreshTokenThreshold",
	"include_claims_in_id_token": "provider.oauth2.includeClaimsInIDToken",
	"signing_key":                "provider.oauth2.signingKey",
	"encryption_key":             "provider.oauth2.encryptionKey",
	"redirect_uris":              "provider.oauth2.redirectURIs",
	"logout_uri":                 "provider.oauth2.logoutURI",
	"logout_method":              "provider.oauth2.logoutMethod",
	"sub_mode":                   "provider.oauth2.subjectMode",
	"issuer_mode":                "provider.oauth2.issuerMode",
}

func proxyFieldPathsFor(proxy *v1alpha1.ProxyProviderSpec) map[string]string {
	paths := maps.Clone(providerFieldPaths)
	maps.Copy(paths, proxyFieldPaths)
	switch {
	case proxy.Proxy != nil:
		paths["external_host"] = "provider.proxy.proxy.externalHost"
	case proxy.ForwardAuthSingle != nil:
		paths["external_host"] = "provider.proxy.forwardAuthSingle.externalHost"
	case proxy.ForwardAuthDomain != nil:
		paths["external_host"] = "provider.proxy.forwardAuthDomain.authenticationURL"
	}
	return paths
}

func oauth2FieldPathsFor() map[string]string {
	paths := maps.Clone(providerFieldPaths)
	maps.Copy(paths, oauth2FieldPaths)
	return paths
}

// toFields converts a client-go model into its JSON fields.
func toFields(model any) map[string]any {
	data, err := json.Marshal(model)
	if err != nil {
		return map[string]any{}
	}
	fields := map[string]any{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return map[string]any{}
	}
	return fields
}

// formatValue renders a JSON value for an adoption diff. Strings are shown without quotes.
func formatValue(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	data, _ := json.Marshal(value)
	return string(data)
}

// fieldDiffs lists the fields of a PATCH request built by the authentik.Diff functions whose values differ from
// the observed object. Fields that the request carries only for server-side validation have equal values and are
// skipped. paths maps API fields to spec paths.
func fieldDiffs(paths map[string]string, patch, observed any) []v1alpha1.FieldDiff {
	desiredFields, observedFields := toFields(patch), toFields(observed)
	diffs := []v1alpha1.FieldDiff{}
	for _, key := range slices.Sorted(maps.Keys(desiredFields)) {
		if reflect.DeepEqual(desiredFields[key], observedFields[key]) {
			continue
		}
		path, ok := paths[key]
		if !ok {
			path = key
		}
		diff := v1alpha1.FieldDiff{Field: path, Desired: formatValue(desiredFields[key]), Actual: formatValue(observedFields[key])}
		if slices.Contains(confidentialFields, key) {
			diff.Desired, diff.Actual = redacted, redacted
		}
		diffs = append(diffs, diff)
	}
	return diffs
}

// adoptApplication decides whether the unmanaged Application is adopted according to spec.adopt
// (docs/spec.md §3.4). It returns nil when the Application is adopted, and a stopError otherwise.
func (r *AuthentikApplicationReconciler) adoptApplication(ctx context.Context, s *reconcileState, observed *api.Application) error {
	policy := v1alpha1.AdoptionPolicyNever
	if s.app.Spec.Adopt != nil {
		policy = *s.app.Spec.Adopt
	}
	if policy == v1alpha1.AdoptionPolicyNever {
		return &stopError{
			reason:  v1alpha1.ReasonUnmanaged,
			message: fmt.Sprintf("Application %q exists in authentik and is not managed by the operator; set spec.adopt to adopt it", observed.Slug),
		}
	}

	provider, err := r.attachedProvider(ctx, s, observed)
	if err != nil {
		return err
	}

	if policy == v1alpha1.AdoptionPolicyIfMatch {
		diffs := []v1alpha1.FieldDiff{}
		if patch, changed := authentik.DiffApplication(desiredApplication(&s.app.Spec, nil), observed); changed {
			diffs = append(diffs, fieldDiffs(applicationFieldPaths, patch, observed)...)
		}
		if provider != nil {
			diffs = append(diffs, provider.diffs()...)
		}
		if len(diffs) > 0 {
			s.app.Status.AdoptionDiff = diffs
			return &stopError{
				reason:  v1alpha1.ReasonAdoptionDiff,
				message: fmt.Sprintf("%d fields differ", len(diffs)),
			}
		}
	}

	r.Recorder.Eventf(s.app, nil, corev1.EventTypeNormal, eventReasonAdopted, eventActionReconcile,
		"Adopted Application %q with adopt %s", observed.Slug, policy)
	return nil
}

// attachedProvider returns the Provider attached to the Application when the spec has a provider. It returns nil
// when no Provider is attached, in which case a new Provider is created and attached, and fails with
// ProviderTypeMismatch when the attached Provider has the other type.
func (r *AuthentikApplicationReconciler) attachedProvider(ctx context.Context, s *reconcileState, application *api.Application) (*observedProvider, error) {
	if s.app.Spec.Provider == nil || application.Provider.Get() == nil {
		return nil, nil
	}
	handler := r.providerHandler(s)
	pk := *application.Provider.Get()
	provider, err := handler.get(ctx, pk)
	if !errors.Is(err, authentik.ErrNotFound) {
		return provider, err
	}
	otherType, err := handler.existsAsOtherType(ctx, pk)
	if err != nil {
		return nil, err
	}
	if otherType {
		return nil, providerTypeMismatch(application.Slug, pk, handler.kind())
	}
	return nil, nil
}

func providerTypeMismatch(slug string, pk int32, kind string) error {
	return &stopError{
		reason:  v1alpha1.ReasonProviderTypeMismatch,
		message: fmt.Sprintf("Application %q has a Provider %d that is not a %s Provider", slug, pk, kind),
	}
}
