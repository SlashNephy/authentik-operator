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

// Package reference resolves the authentik objects and the Secret that an AuthentikApplication references
// (docs/spec.md §3.6). Resolution only reads; callers must not write to authentik when it fails.
package reference

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"

	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

const (
	// EmbeddedOutpostName is the Outpost that a Proxy Provider joins when outpost is omitted (docs/spec.md §2.3).
	EmbeddedOutpostName = "authentik Embedded Outpost"
	// DefaultSigningKeyName is the signing key of an OAuth2 Provider created without signingKey (docs/spec.md §2.3).
	DefaultSigningKeyName = "authentik Self-signed Certificate"
	// DefaultClientIDKey is the Secret key of the client ID when clientIDKey is omitted.
	DefaultClientIDKey = "client-id"
	// DefaultClientSecretKey is the Secret key of the client secret when clientSecretKey is omitted.
	DefaultClientSecretKey = "client-secret"
)

// defaultScopeNames are the scopes of an OAuth2 Provider created without scopes (docs/spec.md §2.3).
var defaultScopeNames = []string{"openid", "email", "profile"}

// nameKey is the name-like key of the objects referenced by NamedReference, used in failure messages.
const nameKey = "name"

// managedScopeMappingPrefix prefixes the managed identifier of the ScopeMappings that authentik ships.
const managedScopeMappingPrefix = "goauthentik.io/providers/oauth2/scope-"

// AuthentikReader is the read-only part of the authentik API that resolution needs.
type AuthentikReader interface {
	authentik.LookupClient
	GetOutpost(ctx context.Context, uuid string) (*api.Outpost, error)
	FindOutpostsByName(ctx context.Context, name string) ([]api.Outpost, error)
}

var _ AuthentikReader = authentik.Client(nil)

// Resolver resolves references of AuthentikApplications.
type Resolver struct {
	authentik AuthentikReader
	kube      client.Reader
}

// NewResolver returns a Resolver that looks up authentik objects with authentikReader and Secrets with kubeReader.
func NewResolver(authentikReader AuthentikReader, kubeReader client.Reader) *Resolver {
	return &Resolver{authentik: authentikReader, kube: kubeReader}
}

// Resolved holds the identifiers of every referenced object.
type Resolved struct {
	// Flows is nil when the spec has no provider.
	Flows *Flows
	// Proxy is nil unless the provider is a Proxy Provider.
	Proxy *ProxyReferences
	// OAuth2 is nil unless the provider is an OAuth2 Provider.
	OAuth2 *OAuth2References
	// Rules correspond to access.rules by index.
	Rules []Rule
}

// Flows holds the UUIDs of the Provider flows.
type Flows struct {
	Authorization  string
	Invalidation   string
	Authentication *string
}

// ProxyReferences holds the objects referenced by a Proxy Provider.
type ProxyReferences struct {
	// Certificate is the CertificateKeyPair UUID, or nil when certificate is omitted.
	Certificate *string
	// Outpost is the Outpost UUID. It is always set because the embedded outpost is the default.
	Outpost string
}

// OAuth2References holds the objects referenced by an OAuth2 Provider.
type OAuth2References struct {
	// Scopes are the ScopeMapping UUIDs, or nil when scopes are omitted.
	Scopes []string
	// SigningKey is the CertificateKeyPair UUID, or nil when signingKey is omitted.
	SigningKey *string
	// EncryptionKey is the CertificateKeyPair UUID, or nil when encryptionKey is omitted.
	EncryptionKey *string
	// Credentials is nil when credentials are omitted.
	Credentials *Credentials
}

// Credentials holds the OAuth2 client credentials read from the Secret (docs/spec.md §2.5).
type Credentials struct {
	// SecretExists reports whether the Secret exists. When it does not, the operator creates it later,
	// ClientSecret is empty, and ClientID is set only when the spec has clientID.
	SecretExists bool
	ClientID     string
	ClientSecret string
}

// Rule is an access rule with its subject resolved. Exactly one of Group, User, and Policy is set.
type Rule struct {
	// Group is the Group UUID.
	Group *string
	// User is the User pk.
	User *int32
	// Policy is the Policy UUID.
	Policy *string
	Negate bool
}

// Resolve resolves every reference in the spec of app, including the default embedded outpost.
// When some references cannot be resolved, it checks all of them and returns an *Error that lists every failure.
// Any other error, such as an authentik API error other than 404, is returned as is and should be retried.
func (r *Resolver) Resolve(ctx context.Context, app *v1alpha1.AuthentikApplication) (*Resolved, error) {
	c := new(collector)
	resolved := &Resolved{Rules: make([]Rule, 0, len(app.Spec.Access.Rules))}

	if provider := app.Spec.Provider; provider != nil {
		var err error
		if resolved.Flows, err = r.resolveFlows(ctx, c, &provider.Flows); err != nil {
			return nil, err
		}
		if provider.Proxy != nil {
			if resolved.Proxy, err = r.resolveProxy(ctx, c, provider.Proxy); err != nil {
				return nil, err
			}
		}
		if provider.OAuth2 != nil {
			if resolved.OAuth2, err = r.resolveOAuth2(ctx, c, app.Namespace, provider.OAuth2); err != nil {
				return nil, err
			}
		}
	}

	for i := range app.Spec.Access.Rules {
		rule, err := r.resolveRule(ctx, c, fmt.Sprintf("access.rules[%d]", i), &app.Spec.Access.Rules[i])
		if err != nil {
			return nil, err
		}
		resolved.Rules = append(resolved.Rules, rule)
	}

	if err := c.err(); err != nil {
		return nil, err
	}
	return resolved, nil
}

// CreationDefaults holds the references applied only when a Provider is created (docs/spec.md §2.3).
type CreationDefaults struct {
	// Scopes are the UUIDs of the default ScopeMappings, or nil when the spec has scopes.
	Scopes []string
	// SigningKey is the UUID of the default signing key, or nil when the spec has signingKey.
	SigningKey *string
}

// ResolveCreationDefaults resolves the defaults of the fields that the OAuth2 provider spec of app omits.
// It returns empty defaults for other provider types. Failures are reported in the same way as Resolve.
// The default scopes are the ScopeMappings that authentik ships, so custom mappings that share a scope name
// do not make them ambiguous.
func (r *Resolver) ResolveCreationDefaults(ctx context.Context, app *v1alpha1.AuthentikApplication) (*CreationDefaults, error) {
	defaults := &CreationDefaults{}
	if app.Spec.Provider == nil || app.Spec.Provider.OAuth2 == nil {
		return defaults, nil
	}
	oauth2 := app.Spec.Provider.OAuth2
	c := new(collector)

	if oauth2.Scopes == nil {
		defaults.Scopes = make([]string, 0, len(defaultScopeNames))
		for _, scopeName := range defaultScopeNames {
			pk, err := r.resolveDefaultScopeMapping(ctx, c, scopeName)
			if err != nil {
				return nil, err
			}
			defaults.Scopes = append(defaults.Scopes, pk)
		}
	}

	if oauth2.SigningKey == nil {
		pk, err := resolveByString(ctx, c, "provider.oauth2.signingKey", r.keyPairLookup(), nil, new(DefaultSigningKeyName))
		if err != nil {
			return nil, err
		}
		defaults.SigningKey = &pk
	}

	if err := c.err(); err != nil {
		return nil, err
	}
	return defaults, nil
}

func (r *Resolver) resolveFlows(ctx context.Context, c *collector, flows *v1alpha1.ProviderFlows) (*Flows, error) {
	lookup := r.flowLookup()
	authorization, err := resolveByString(ctx, c, "provider.flows.authorization", lookup, flows.Authorization.UUID, flows.Authorization.Slug)
	if err != nil {
		return nil, err
	}
	invalidation, err := resolveByString(ctx, c, "provider.flows.invalidation", lookup, flows.Invalidation.UUID, flows.Invalidation.Slug)
	if err != nil {
		return nil, err
	}
	resolved := &Flows{Authorization: authorization, Invalidation: invalidation}
	if ref := flows.Authentication; ref != nil {
		authentication, err := resolveByString(ctx, c, "provider.flows.authentication", lookup, ref.UUID, ref.Slug)
		if err != nil {
			return nil, err
		}
		resolved.Authentication = &authentication
	}
	return resolved, nil
}

func (r *Resolver) resolveProxy(ctx context.Context, c *collector, proxy *v1alpha1.ProxyProviderSpec) (*ProxyReferences, error) {
	resolved := &ProxyReferences{}
	var err error
	if resolved.Certificate, err = resolveNamed(ctx, c, "provider.proxy.certificate", r.keyPairLookup(), proxy.Certificate); err != nil {
		return nil, err
	}
	outpost := cmp.Or(proxy.Outpost, &v1alpha1.NamedReference{Name: new(EmbeddedOutpostName)})
	if resolved.Outpost, err = resolveByString(ctx, c, "provider.proxy.outpost", r.outpostLookup(), outpost.UUID, outpost.Name); err != nil {
		return nil, err
	}
	return resolved, nil
}

func (r *Resolver) resolveOAuth2(ctx context.Context, c *collector, namespace string, oauth2 *v1alpha1.OAuth2ProviderSpec) (*OAuth2References, error) {
	resolved := &OAuth2References{}
	var err error

	if oauth2.Scopes != nil {
		resolved.Scopes = make([]string, 0, len(oauth2.Scopes))
		lookup := r.scopeMappingLookup()
		for i, ref := range oauth2.Scopes {
			pk, err := resolveByString(ctx, c, fmt.Sprintf("provider.oauth2.scopes[%d]", i), lookup, ref.UUID, ref.ScopeName)
			if err != nil {
				return nil, err
			}
			resolved.Scopes = append(resolved.Scopes, pk)
		}
	}
	if resolved.SigningKey, err = resolveNamed(ctx, c, "provider.oauth2.signingKey", r.keyPairLookup(), oauth2.SigningKey); err != nil {
		return nil, err
	}
	if resolved.EncryptionKey, err = resolveNamed(ctx, c, "provider.oauth2.encryptionKey", r.keyPairLookup(), oauth2.EncryptionKey); err != nil {
		return nil, err
	}
	if oauth2.Credentials != nil {
		if resolved.Credentials, err = r.resolveCredentials(ctx, c, namespace, oauth2.Credentials); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

// resolveCredentials reads the credentials Secret. A missing Secret is not a failure because the operator
// creates it, but a missing key in an existing Secret is (docs/spec.md §2.5).
func (r *Resolver) resolveCredentials(ctx context.Context, c *collector, namespace string, spec *v1alpha1.OAuth2CredentialsSpec) (*Credentials, error) {
	ref := &spec.SecretRef
	secret := &corev1.Secret{}
	if err := r.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			credentials := &Credentials{}
			if spec.ClientID != nil {
				credentials.ClientID = *spec.ClientID
			}
			return credentials, nil
		}
		return nil, fmt.Errorf("failed to get Secret %s/%s: %w", namespace, ref.Name, err)
	}

	credentials := &Credentials{SecretExists: true}
	readKey := func(path string, key *string, defaultKey string) string {
		name := cmp.Or(key, &defaultKey)
		value, ok := secret.Data[*name]
		if !ok {
			c.add(path, fmt.Sprintf("key %q in Secret %q", *name, ref.Name), 0)
		}
		return string(value)
	}
	if spec.ClientID != nil {
		credentials.ClientID = *spec.ClientID
	} else {
		credentials.ClientID = readKey("provider.oauth2.credentials.secretRef.clientIDKey", ref.ClientIDKey, DefaultClientIDKey)
	}
	credentials.ClientSecret = readKey("provider.oauth2.credentials.secretRef.clientSecretKey", ref.ClientSecretKey, DefaultClientSecretKey)
	return credentials, nil
}

func (r *Resolver) resolveRule(ctx context.Context, c *collector, path string, rule *v1alpha1.AccessRule) (Rule, error) {
	resolved := Rule{Negate: rule.Negate != nil && *rule.Negate}
	var err error
	switch {
	case rule.Group != nil:
		resolved.Group, err = resolveNamed(ctx, c, path+".group", r.groupLookup(), rule.Group)
	case rule.User != nil:
		resolved.User, err = r.resolveUser(ctx, c, path+".user", rule.User)
	case rule.Policy != nil:
		resolved.Policy, err = resolveNamed(ctx, c, path+".policy", r.policyLookup(), rule.Policy)
	}
	return resolved, err
}

func (r *Resolver) resolveUser(ctx context.Context, c *collector, path string, ref *v1alpha1.UserReference) (*int32, error) {
	if ref.PK != nil {
		target := fmt.Sprintf("User pk %d", *ref.PK)
		if *ref.PK < 1 || *ref.PK > math.MaxInt32 {
			// authentik stores User pks as 32-bit integers, so no User can have this pk.
			c.add(path, target, 0)
			return nil, nil
		}
		user, err := getOne(c, path, target, func() (*api.User, error) { return r.authentik.GetUser(ctx, int32(*ref.PK)) })
		if err != nil || user == nil {
			return nil, err
		}
		return &user.Pk, nil
	}
	target := fmt.Sprintf("User username %q", *ref.Username)
	user, err := findOne(c, path, target, func() ([]api.User, error) { return r.authentik.FindUsersByUsername(ctx, *ref.Username) })
	if err != nil || user == nil {
		return nil, err
	}
	return &user.Pk, nil
}

func (r *Resolver) resolveDefaultScopeMapping(ctx context.Context, c *collector, scopeName string) (string, error) {
	mappings, err := r.authentik.FindScopeMappingsByScopeName(ctx, scopeName)
	if err != nil {
		return "", fmt.Errorf("failed to resolve provider.oauth2.scopes: %w", err)
	}
	managed := managedScopeMappingPrefix + scopeName
	var found []api.ScopeMapping
	for _, mapping := range mappings {
		if value, ok := mapping.GetManagedOk(); ok && value != nil && *value == managed {
			found = append(found, mapping)
		}
	}
	if len(found) != 1 {
		c.add("provider.oauth2.scopes", fmt.Sprintf("ScopeMapping managed %q", managed), len(found))
		return "", nil
	}
	return found[0].Pk, nil
}

// stringLookup describes how to resolve one kind of authentik object whose identifier is a UUID string.
type stringLookup[T any] struct {
	// kind is the object kind used in failure messages, such as Group.
	kind string
	// keyName is the name-like key used in failure messages, such as name.
	keyName string
	get     func(ctx context.Context, uuid string) (*T, error)
	find    func(ctx context.Context, key string) ([]T, error)
	pk      func(*T) string
}

func (r *Resolver) flowLookup() stringLookup[api.Flow] {
	return stringLookup[api.Flow]{
		kind: "Flow", keyName: "slug",
		get: r.authentik.GetFlow, find: r.authentik.FindFlowsBySlug,
		pk: func(flow *api.Flow) string { return flow.Pk },
	}
}

func (r *Resolver) keyPairLookup() stringLookup[api.CertificateKeyPair] {
	return stringLookup[api.CertificateKeyPair]{
		kind: "CertificateKeyPair", keyName: nameKey,
		get: r.authentik.GetCertificateKeyPair, find: r.authentik.FindCertificateKeyPairsByName,
		pk: func(keyPair *api.CertificateKeyPair) string { return keyPair.Pk },
	}
}

func (r *Resolver) outpostLookup() stringLookup[api.Outpost] {
	return stringLookup[api.Outpost]{
		kind: "Outpost", keyName: nameKey,
		get: r.authentik.GetOutpost, find: r.authentik.FindOutpostsByName,
		pk: func(outpost *api.Outpost) string { return outpost.Pk },
	}
}

func (r *Resolver) scopeMappingLookup() stringLookup[api.ScopeMapping] {
	return stringLookup[api.ScopeMapping]{
		kind: "ScopeMapping", keyName: "scopeName",
		get: r.authentik.GetScopeMapping, find: r.authentik.FindScopeMappingsByScopeName,
		pk: func(mapping *api.ScopeMapping) string { return mapping.Pk },
	}
}

func (r *Resolver) groupLookup() stringLookup[api.Group] {
	return stringLookup[api.Group]{
		kind: "Group", keyName: nameKey,
		get: r.authentik.GetGroup, find: r.authentik.FindGroupsByName,
		pk: func(group *api.Group) string { return group.Pk },
	}
}

func (r *Resolver) policyLookup() stringLookup[api.Policy] {
	return stringLookup[api.Policy]{
		kind: "Policy", keyName: nameKey,
		get: r.authentik.GetPolicy, find: r.authentik.FindPoliciesByName,
		pk: func(policy *api.Policy) string { return policy.Pk },
	}
}

// resolveNamed resolves an optional NamedReference. It returns nil when ref is nil or cannot be resolved.
func resolveNamed[T any](ctx context.Context, c *collector, path string, lookup stringLookup[T], ref *v1alpha1.NamedReference) (*string, error) {
	if ref == nil {
		return nil, nil
	}
	failures := len(c.failures)
	pk, err := resolveByString(ctx, c, path, lookup, ref.UUID, ref.Name)
	if err != nil || len(c.failures) > failures {
		return nil, err
	}
	return &pk, nil
}

// resolveByString resolves a reference by uuid when it is set, and otherwise by the name-like key.
// It returns an empty string when the reference cannot be resolved and records the failure in c.
func resolveByString[T any](ctx context.Context, c *collector, path string, lookup stringLookup[T], uuid, key *string) (string, error) {
	var object *T
	var err error
	if uuid != nil {
		target := fmt.Sprintf("%s uuid %q", lookup.kind, *uuid)
		object, err = getOne(c, path, target, func() (*T, error) { return lookup.get(ctx, *uuid) })
	} else {
		target := fmt.Sprintf("%s %s %q", lookup.kind, lookup.keyName, *key)
		object, err = findOne(c, path, target, func() ([]T, error) { return lookup.find(ctx, *key) })
	}
	if err != nil || object == nil {
		return "", err
	}
	return lookup.pk(object), nil
}

// getOne fetches an object by identifier. A 404 is recorded in c and yields a nil object without error.
func getOne[T any](c *collector, path, target string, get func() (*T, error)) (*T, error) {
	object, err := get()
	if errors.Is(err, authentik.ErrNotFound) {
		c.add(path, target, 0)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", path, err)
	}
	return object, nil
}

// findOne searches an object by a name-like key. Zero or several matches are recorded in c and yield a nil object
// without error.
func findOne[T any](c *collector, path, target string, find func() ([]T, error)) (*T, error) {
	objects, err := find()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", path, err)
	}
	if len(objects) != 1 {
		c.add(path, target, len(objects))
		return nil, nil
	}
	return &objects[0], nil
}
