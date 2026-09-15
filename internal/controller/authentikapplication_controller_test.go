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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik/fake"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

const (
	testRole          = "authentik-operator-test"
	authorizationSlug = "default-provider-authorization-implicit-consent"
	invalidationSlug  = "default-provider-invalidation-flow"
	externalHost      = "https://wiki.example.com"
	resyncInterval    = 10 * time.Minute
	testName          = "Wiki"
	oauth2Slug        = "chat"
	normalCreated     = "Normal Created"

	opCreatePolicyBinding    = "CreatePolicyBinding"
	opAssignObjectPermission = "AssignObjectPermission"
	opDeletePolicyBinding    = "DeletePolicyBinding"
)

// defaultScopes are the scopes of an OAuth2 Provider created without scopes.
var defaultScopes = []string{"openid", "email", "profile"}

// recordingClient records the write operations sent to the fake authentik.
type recordingClient struct {
	*fake.Client

	mu     sync.Mutex
	writes []string
}

func (c *recordingClient) record(operation string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, operation)
}

// takeWrites returns the recorded write operations and clears them.
func (c *recordingClient) takeWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	writes := c.writes
	c.writes = nil
	return writes
}

func (c *recordingClient) CreateApplication(ctx context.Context, request *api.ApplicationRequest) (*api.Application, error) {
	c.record("CreateApplication")
	return c.Client.CreateApplication(ctx, request)
}

func (c *recordingClient) PatchApplication(ctx context.Context, slug string, request *api.PatchedApplicationRequest) (*api.Application, error) {
	c.record("PatchApplication")
	return c.Client.PatchApplication(ctx, slug, request)
}

func (c *recordingClient) CreateProxyProvider(ctx context.Context, request *api.ProxyProviderRequest) (*api.ProxyProvider, error) {
	c.record("CreateProxyProvider")
	return c.Client.CreateProxyProvider(ctx, request)
}

func (c *recordingClient) PatchProxyProvider(ctx context.Context, pk int32, request *api.PatchedProxyProviderRequest) (*api.ProxyProvider, error) {
	c.record("PatchProxyProvider")
	return c.Client.PatchProxyProvider(ctx, pk, request)
}

func (c *recordingClient) CreateOAuth2Provider(ctx context.Context, request *api.OAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	c.record("CreateOAuth2Provider")
	return c.Client.CreateOAuth2Provider(ctx, request)
}

func (c *recordingClient) PatchOAuth2Provider(ctx context.Context, pk int32, request *api.PatchedOAuth2ProviderRequest) (*api.OAuth2Provider, error) {
	c.record("PatchOAuth2Provider")
	return c.Client.PatchOAuth2Provider(ctx, pk, request)
}

func (c *recordingClient) CreatePolicyBinding(ctx context.Context, request *api.PolicyBindingRequest) (*api.PolicyBinding, error) {
	c.record(opCreatePolicyBinding)
	return c.Client.CreatePolicyBinding(ctx, request)
}

func (c *recordingClient) PatchPolicyBinding(ctx context.Context, uuid string, request *api.PatchedPolicyBindingRequest) (*api.PolicyBinding, error) {
	c.record("PatchPolicyBinding")
	return c.Client.PatchPolicyBinding(ctx, uuid, request)
}

func (c *recordingClient) DeletePolicyBinding(ctx context.Context, uuid string) error {
	c.record(opDeletePolicyBinding)
	return c.Client.DeletePolicyBinding(ctx, uuid)
}

func (c *recordingClient) AssignObjectPermission(ctx context.Context, roleUUID string, model api.ModelEnum, objectPK, permission string) error {
	c.record(opAssignObjectPermission)
	return c.Client.AssignObjectPermission(ctx, roleUUID, model, objectPK, permission)
}

// fixture is an authentik fake with the objects that test resources reference, and a reconciler that uses it.
type fixture struct {
	authentik  *recordingClient
	reconciler *AuthentikApplicationReconciler
	recorder   *events.FakeRecorder
	namespace  string
	// slug is unique to the fixture, because the slug index is cluster-wide and tests run in parallel.
	slug string

	admins *api.Group
	bob    *api.User
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	c := &recordingClient{Client: fake.New()}
	c.AddFlow(authorizationSlug)
	c.AddFlow(invalidationSlug)
	c.AddOutpost(reference.EmbeddedOutpostName)
	c.AddCertificateKeyPair(reference.DefaultSigningKeyName)
	for _, scope := range defaultScopes {
		c.AddManagedScopeMapping("OpenID '"+scope+"'", scope, "goauthentik.io/providers/oauth2/scope-"+scope)
	}

	namespace := &corev1.Namespace{GenerateName: "test-"}
	require.NoError(t, k8sClient.Create(t.Context(), namespace))

	recorder := events.NewFakeRecorder(100)
	return &fixture{
		authentik: c,
		reconciler: &AuthentikApplicationReconciler{
			Client:         indexedClient,
			Scheme:         scheme,
			Authentik:      c,
			Marker:         ownership.NewMarker(c, testRole),
			Resolver:       reference.NewResolver(c, k8sClient),
			Recorder:       recorder,
			ResyncInterval: resyncInterval,
		},
		recorder:  recorder,
		namespace: namespace.Name,
		slug:      namespace.Name,
		admins:    c.AddGroup("admins"),
		bob:       c.AddUser("bob"),
	}
}

func testProviderFlows() v1alpha1.ProviderFlows {
	return v1alpha1.ProviderFlows{
		Authorization: v1alpha1.FlowReference{Slug: new(authorizationSlug)},
		Invalidation:  v1alpha1.FlowReference{Slug: new(invalidationSlug)},
	}
}

func (f *fixture) proxySpec() v1alpha1.AuthentikApplicationSpec {
	return v1alpha1.AuthentikApplicationSpec{
		Slug:      f.slug,
		Name:      testName,
		LaunchURL: new(externalHost),
		Provider: &v1alpha1.ProviderSpec{
			Flows: testProviderFlows(),
			Proxy: &v1alpha1.ProxyProviderSpec{ForwardAuthSingle: &v1alpha1.ForwardAuthSingleSpec{ExternalHost: externalHost}},
		},
		Access: v1alpha1.AccessSpec{Rules: []v1alpha1.AccessRule{
			{Group: &v1alpha1.NamedReference{Name: new("admins")}},
			{User: &v1alpha1.UserReference{Username: new("bob")}, Negate: new(true)},
		}},
	}
}

// create creates the resource in envtest.
func (f *fixture) create(t *testing.T, spec v1alpha1.AuthentikApplicationSpec) *v1alpha1.AuthentikApplication {
	t.Helper()
	app := &v1alpha1.AuthentikApplication{Namespace: f.namespace, Name: spec.Slug, Spec: spec}
	require.NoError(t, k8sClient.Create(t.Context(), app))
	return app
}

// reconcile runs one reconcile and returns the result, the resource read back from envtest, and the error.
func (f *fixture) reconcile(t *testing.T, app *v1alpha1.AuthentikApplication) (ctrl.Result, *v1alpha1.AuthentikApplication, error) {
	t.Helper()
	key := client.ObjectKeyFromObject(app)
	result, err := f.reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	got := &v1alpha1.AuthentikApplication{}
	require.NoError(t, k8sClient.Get(t.Context(), key, got))
	return result, got, err
}

// events returns the recorded events and clears them.
func (f *fixture) events() []string {
	var recorded []string
	for {
		select {
		case event := <-f.recorder.Events:
			recorded = append(recorded, event)
		default:
			return recorded
		}
	}
}

// managed returns the objects that carry the marker.
func (f *fixture) managed(t *testing.T) []ownership.Object {
	t.Helper()
	set, err := ownership.NewMarker(f.authentik.Client, testRole).ListManaged(t.Context())
	require.NoError(t, err)
	return set.Objects()
}

func assertReady(t *testing.T, app *v1alpha1.AuthentikApplication, status metav1.ConditionStatus, reason string) {
	t.Helper()
	condition := meta.FindStatusCondition(app.Status.Conditions, v1alpha1.ConditionTypeReady)
	require.NotNil(t, condition)
	assert.Equal(t, status, condition.Status, condition.Message)
	assert.Equal(t, reason, condition.Reason, condition.Message)
	assert.Equal(t, app.Generation, app.Status.ObservedGeneration)
}

func eventReasons(recorded []string) []string {
	reasons := make([]string, 0, len(recorded))
	for _, event := range recorded {
		fields := strings.Fields(event)
		reasons = append(reasons, fields[0]+" "+fields[1])
	}
	return reasons
}

func providerObject(model api.ModelEnum, pk *int64) ownership.Object {
	return ownership.Object{Model: model, PK: strconv.FormatInt(*pk, 10)}
}

func TestReconcileCreatesProxyApplication(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())

	result, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	assert.Equal(t, resyncInterval, result.RequeueAfter)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Equal(t, specHash(&got.Spec), got.Status.LastAppliedHash)
	assert.Equal(t, f.slug, got.Status.ApplicationSlug)
	require.NotNil(t, got.Status.ProviderPK)

	application, err := f.authentik.GetApplication(t.Context(), f.slug)
	require.NoError(t, err)
	assert.Equal(t, got.Status.ApplicationPK, application.Pk)
	assert.Equal(t, testName, application.Name)
	assert.Equal(t, new(externalHost), application.MetaLaunchUrl)
	assert.Equal(t, new(api.POLICYENGINEMODE_ANY), application.PolicyEngineMode, "the CRD default of access.mode is applied")
	assert.Equal(t, new(int32(*got.Status.ProviderPK)), application.Provider.Get())

	provider, err := f.authentik.GetProxyProvider(t.Context(), int32(*got.Status.ProviderPK))
	require.NoError(t, err)
	assert.Equal(t, f.slug, provider.Name, "the provider name defaults to the slug")
	assert.Equal(t, new(api.PROXYMODE_FORWARD_SINGLE), provider.Mode)
	assert.Equal(t, externalHost, provider.ExternalHost)

	bindings, err := f.authentik.ListPolicyBindings(t.Context(), application.PbmUuid)
	require.NoError(t, err)
	require.Len(t, bindings, 2)
	assert.Equal(t, new(f.admins.Pk), bindings[0].Group.Get())
	assert.Equal(t, new(false), bindings[0].Negate)
	assert.Equal(t, int32(10), bindings[0].Order)
	assert.Equal(t, new(f.bob.Pk), bindings[1].User.Get())
	assert.Equal(t, new(true), bindings[1].Negate)
	assert.Equal(t, int32(20), bindings[1].Order)
	assert.ElementsMatch(t, []string{bindings[0].Pk, bindings[1].Pk}, got.Status.BindingUUIDs)

	assert.ElementsMatch(t, []ownership.Object{
		{Model: ownership.ModelApplication, PK: application.Pk},
		providerObject(ownership.ModelProxyProvider, got.Status.ProviderPK),
		{Model: ownership.ModelPolicyBinding, PK: bindings[0].Pk},
		{Model: ownership.ModelPolicyBinding, PK: bindings[1].Pk},
	}, f.managed(t))

	assert.Equal(t, []string{normalCreated, normalCreated, "Normal Reconciled"}, eventReasons(f.events()))
}

func TestReconcileCreatesOAuth2ApplicationWithDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, v1alpha1.AuthentikApplicationSpec{
		Slug: f.slug, Name: "Chat",
		Provider: &v1alpha1.ProviderSpec{Flows: testProviderFlows(), OAuth2: &v1alpha1.OAuth2ProviderSpec{ClientType: new(v1alpha1.ClientTypePublic)}},
		Access:   v1alpha1.AccessSpec{Public: new(true)},
	})

	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Empty(t, got.Status.BindingUUIDs)

	provider, err := f.authentik.GetOAuth2Provider(t.Context(), int32(*got.Status.ProviderPK))
	require.NoError(t, err)
	assert.Equal(t, f.slug, provider.Name)
	assert.Len(t, provider.PropertyMappings, 3, "openid, email, and profile are the default scopes")
	assert.NotNil(t, provider.SigningKey.Get(), "the self-signed certificate is the default signing key")
	assert.Equal(t, new(api.CLIENTTYPEENUM_PUBLIC), provider.ClientType)

	application, err := f.authentik.GetApplication(t.Context(), f.slug)
	require.NoError(t, err)
	bindings, err := f.authentik.ListPolicyBindings(t.Context(), application.PbmUuid)
	require.NoError(t, err)
	assert.Empty(t, bindings)
}

func TestReconcileWithoutChangesWritesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())

	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	f.authentik.takeWrites()
	f.events()

	_, again, err := f.reconcile(t, got)
	require.NoError(t, err)
	assert.Empty(t, f.authentik.takeWrites())
	assert.Empty(t, f.events(), "no Event is recorded without a state transition")
	assert.Equal(t, got.ResourceVersion, again.ResourceVersion, "the status is not written again")
}

func TestReconcileRepairsDrift(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())
	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)

	ctx := t.Context()
	providerPK := int32(*got.Status.ProviderPK)
	_, err = f.authentik.PatchApplication(ctx, f.slug, &api.PatchedApplicationRequest{
		Name: new("Changed"), MetaDescription: new("set in the UI"), Provider: *api.NewNullableInt32(nil),
	})
	require.NoError(t, err)
	_, err = f.authentik.PatchProxyProvider(ctx, providerPK, &api.PatchedProxyProviderRequest{
		Mode: new(api.PROXYMODE_FORWARD_SINGLE), ExternalHost: new("https://changed.example.com"),
	})
	require.NoError(t, err)
	binding, err := f.authentik.GetPolicyBinding(ctx, got.Status.BindingUUIDs[0])
	require.NoError(t, err)
	_, err = f.authentik.PatchPolicyBinding(ctx, binding.Pk, &api.PatchedPolicyBindingRequest{
		Target: new(binding.Target), Group: binding.Group, Negate: new(true),
	})
	require.NoError(t, err)
	f.authentik.takeWrites()

	_, _, err = f.reconcile(t, got)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"PatchApplication", "PatchProxyProvider", "PatchPolicyBinding"}, f.authentik.takeWrites())

	application, err := f.authentik.GetApplication(ctx, f.slug)
	require.NoError(t, err)
	assert.Equal(t, testName, application.Name)
	assert.Equal(t, new("set in the UI"), application.MetaDescription, "fields omitted from the spec are not managed")
	assert.Equal(t, new(providerPK), application.Provider.Get())
	provider, err := f.authentik.GetProxyProvider(ctx, providerPK)
	require.NoError(t, err)
	assert.Equal(t, externalHost, provider.ExternalHost)
	binding, err = f.authentik.GetPolicyBinding(ctx, binding.Pk)
	require.NoError(t, err)
	assert.Equal(t, new(false), binding.Negate)
}

func TestReconcileRecreatesDeletedObjects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())
	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	f.events()

	ctx := t.Context()
	require.NoError(t, f.authentik.DeleteApplication(ctx, f.slug))
	require.NoError(t, f.authentik.DeleteProxyProvider(ctx, int32(*got.Status.ProviderPK)))

	_, recreated, err := f.reconcile(t, got)
	require.NoError(t, err)
	assertReady(t, recreated, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.NotEqual(t, got.Status.ApplicationPK, recreated.Status.ApplicationPK)
	assert.NotEqual(t, *got.Status.ProviderPK, *recreated.Status.ProviderPK)
	assert.Len(t, recreated.Status.BindingUUIDs, 2)
	assert.ElementsMatch(t, []string{"Warning Recreated", "Warning Recreated", normalCreated, normalCreated}, eventReasons(f.events()))

	application, err := f.authentik.GetApplication(ctx, f.slug)
	require.NoError(t, err)
	assert.Equal(t, new(int32(*recreated.Status.ProviderPK)), application.Provider.Get())
}

func TestReconcileReusesProviderWithoutApplication(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	flows, err := f.authentik.FindFlowsBySlug(t.Context(), authorizationSlug)
	require.NoError(t, err)
	// A Provider left behind by a crash before its pk was recorded: it has the default name and no marker.
	orphan, err := f.authentik.CreateProxyProvider(t.Context(), &api.ProxyProviderRequest{
		Name: f.slug, AuthorizationFlow: flows[0].Pk, InvalidationFlow: flows[0].Pk,
		ExternalHost: "https://old.example.com", Mode: new(api.PROXYMODE_FORWARD_SINGLE),
	})
	require.NoError(t, err)
	f.authentik.takeWrites()

	_, got, err := f.reconcile(t, f.create(t, f.proxySpec()))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Equal(t, int64(orphan.Pk), *got.Status.ProviderPK)
	assert.NotContains(t, f.authentik.takeWrites(), "CreateProxyProvider")
	assert.Contains(t, f.managed(t), ownership.Object{Model: ownership.ModelProxyProvider, PK: strconv.Itoa(int(orphan.Pk))})

	provider, err := f.authentik.GetProxyProvider(t.Context(), orphan.Pk)
	require.NoError(t, err)
	assert.Equal(t, externalHost, provider.ExternalHost, "the reused Provider is brought to the spec")
}

func TestReconcileStopsWithoutWriting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup prepares authentik and returns the spec.
		setup      func(t *testing.T, f *fixture) v1alpha1.AuthentikApplicationSpec
		reason     string
		wantErr    bool
		wantResync bool
	}{
		{
			name: "unresolved reference",
			setup: func(_ *testing.T, f *fixture) v1alpha1.AuthentikApplicationSpec {
				spec := f.proxySpec()
				spec.Access.Rules = append(spec.Access.Rules, v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("missing")}})
				return spec
			},
			reason:  v1alpha1.ReasonReferenceNotFound,
			wantErr: true,
		},
		{
			name: "unmanaged Application with the slug",
			setup: func(t *testing.T, f *fixture) v1alpha1.AuthentikApplicationSpec {
				_, err := f.authentik.CreateApplication(t.Context(), &api.ApplicationRequest{Name: "Manual", Slug: f.slug})
				require.NoError(t, err)
				return f.proxySpec()
			},
			reason:     v1alpha1.ReasonUnmanaged,
			wantResync: true,
		},
		{
			name: "managed Application with a Provider of another type",
			setup: func(t *testing.T, f *fixture) v1alpha1.AuthentikApplicationSpec {
				ctx := t.Context()
				flows, err := f.authentik.FindFlowsBySlug(ctx, authorizationSlug)
				require.NoError(t, err)
				provider, err := f.authentik.CreateOAuth2Provider(ctx, &api.OAuth2ProviderRequest{
					Name: "other", AuthorizationFlow: flows[0].Pk, InvalidationFlow: flows[0].Pk, RedirectUris: []api.RedirectURIRequest{},
				})
				require.NoError(t, err)
				application, err := f.authentik.CreateApplication(ctx, &api.ApplicationRequest{
					Name: testName, Slug: f.slug, Provider: *api.NewNullableInt32(&provider.Pk),
				})
				require.NoError(t, err)
				require.NoError(t, ownership.NewMarker(f.authentik.Client, testRole).Mark(ctx, applicationObject(application)))
				return f.proxySpec()
			},
			reason:     v1alpha1.ReasonProviderTypeMismatch,
			wantResync: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			spec := tt.setup(t, f)
			f.authentik.takeWrites()

			result, got, err := f.reconcile(t, f.create(t, spec))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.wantResync {
				assert.Equal(t, resyncInterval, result.RequeueAfter)
			}
			assertReady(t, got, metav1.ConditionFalse, tt.reason)
			assert.Empty(t, f.authentik.takeWrites())
			assert.Equal(t, []string{"Warning " + tt.reason}, eventReasons(f.events()))
		})
	}
}

func TestReconcileUpdatesBindingsWhenRulesChange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())
	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)

	ctx := t.Context()
	application, err := f.authentik.GetApplication(ctx, f.slug)
	require.NoError(t, err)
	unmanaged, err := f.authentik.CreatePolicyBinding(ctx, &api.PolicyBindingRequest{
		Target: application.PbmUuid, Group: *api.NewNullableString(new(f.authentik.AddGroup("legacy").Pk)), Order: 100,
	})
	require.NoError(t, err)

	developers := f.authentik.AddGroup("developers")
	got.Spec.Access.Rules = []v1alpha1.AccessRule{
		{Group: &v1alpha1.NamedReference{Name: new("admins")}},
		{Group: &v1alpha1.NamedReference{Name: new("developers")}},
	}
	require.NoError(t, k8sClient.Update(ctx, got))
	f.authentik.takeWrites()

	_, updated, err := f.reconcile(t, got)
	require.NoError(t, err)
	assert.Equal(t, []string{opCreatePolicyBinding, opAssignObjectPermission, opDeletePolicyBinding}, f.authentik.takeWrites(),
		"the new Binding is written before the old one is deleted")

	bindings, err := f.authentik.ListPolicyBindings(ctx, application.PbmUuid)
	require.NoError(t, err)
	// The Bindings are listed by order: admins (10), the unmanaged one (100), and developers (110).
	require.Len(t, bindings, 3)
	assert.Equal(t, new(f.admins.Pk), bindings[0].Group.Get())
	assert.Equal(t, unmanaged.Pk, bindings[1].Pk, "an unmanaged Binding is kept")
	assert.Equal(t, new(developers.Pk), bindings[2].Group.Get())
	assert.Equal(t, int32(110), bindings[2].Order, "the order follows the largest existing order")
	assert.ElementsMatch(t, []string{bindings[0].Pk, bindings[2].Pk}, updated.Status.BindingUUIDs)
	assert.Equal(t, got.Generation, updated.Status.ObservedGeneration)
}

func TestReconcileReattachesMarkersAfterRoleRecreation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := f.create(t, f.proxySpec())
	_, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	before := f.managed(t)

	role, err := f.authentik.FindRolesByName(t.Context(), testRole)
	require.NoError(t, err)
	f.authentik.DeleteRole(role[0].Pk)
	// Let the cached marker list expire, as it does at the next resync.
	now := time.Now()
	f.reconciler.markers().now = func() time.Time { return now.Add(resyncInterval) }

	_, again, err := f.reconcile(t, got)
	require.NoError(t, err)
	assertReady(t, again, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.ElementsMatch(t, before, f.managed(t))
}

func TestManagerReconcilesResources(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		// go test -count runs this test again in the same process, which registers the controller name again.
		Controller: config.Controller{SkipNameValidation: new(true)},
		// Other tests reconcile the resources in their own namespaces with their own fakes.
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{f.namespace: {}}},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	require.NoError(t, err)
	reconciler := f.reconciler
	reconciler.Client = mgr.GetClient()
	reconciler.Resolver = reference.NewResolver(f.authentik, mgr.GetClient())
	require.NoError(t, reconciler.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		assert.NoError(t, mgr.Start(ctx))
	}()

	app := f.create(t, f.proxySpec())
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		got := &v1alpha1.AuthentikApplication{}
		require.NoError(c, k8sClient.Get(ctx, client.ObjectKeyFromObject(app), got))
		condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeReady)
		require.NotNil(c, condition)
		assert.Equal(c, metav1.ConditionTrue, condition.Status)
	}, 30*time.Second, 100*time.Millisecond)
}

func TestConflictWinner(t *testing.T) {
	t.Parallel()

	const secondWiki = "b/wiki"
	older := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := metav1.NewTime(older.Add(time.Hour))
	app := func(namespace, name string, created metav1.Time, applicationPK string) v1alpha1.AuthentikApplication {
		return v1alpha1.AuthentikApplication{
			Namespace: namespace, Name: name, CreationTimestamp: created,
			Status: v1alpha1.AuthentikApplicationStatus{ApplicationPK: applicationPK},
		}
	}

	tests := []struct {
		name       string
		candidates []v1alpha1.AuthentikApplication
		want       string
	}{
		{
			name:       "single resource",
			candidates: []v1alpha1.AuthentikApplication{app("a", "wiki", newer, "")},
			want:       "a/wiki",
		},
		{
			name:       "oldest resource when none has recorded a pk",
			candidates: []v1alpha1.AuthentikApplication{app("a", "wiki", newer, ""), app("b", "wiki", older, "")},
			want:       secondWiki,
		},
		{
			name:       "resource with a recorded pk wins over an older one",
			candidates: []v1alpha1.AuthentikApplication{app("a", "wiki", older, ""), app("b", "wiki", newer, "pk")},
			want:       secondWiki,
		},
		{
			name:       "oldest resource among those with a recorded pk",
			candidates: []v1alpha1.AuthentikApplication{app("a", "wiki", newer, "pk"), app("b", "wiki", older, "pk"), app("c", "wiki", older, "")},
			want:       secondWiki,
		},
		{
			name:       "namespace and name break a tie",
			candidates: []v1alpha1.AuthentikApplication{app("b", "wiki", older, ""), app("a", "z", older, ""), app("a", "y", older, "")},
			want:       "a/y",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			winner := conflictWinner(tt.candidates)
			assert.Equal(t, tt.want, winner.Namespace+"/"+winner.Name)
		})
	}
}

// waitForSlugIndex waits until the cached slug index lists count resources with the slug.
func waitForSlugIndex(t *testing.T, slug string, count int) {
	t.Helper()
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var list v1alpha1.AuthentikApplicationList
		require.NoError(c, indexedClient.List(t.Context(), &list, client.MatchingFields{slugIndexField: slug}))
		assert.Len(c, list.Items, count)
	}, 10*time.Second, 50*time.Millisecond)
}

func TestReconcileConflict(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	slug := f.slug

	first := f.proxySpec()
	winner := &v1alpha1.AuthentikApplication{Namespace: f.namespace, Name: "a-first", Spec: first}
	require.NoError(t, k8sClient.Create(t.Context(), winner))
	loser := &v1alpha1.AuthentikApplication{Namespace: f.namespace, Name: "b-second", Spec: first}
	require.NoError(t, k8sClient.Create(t.Context(), loser))
	waitForSlugIndex(t, slug, 2)

	result, got, err := f.reconcile(t, loser)
	require.NoError(t, err)
	assert.Equal(t, resyncInterval, result.RequeueAfter)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonConflict)
	assert.Contains(t, meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeReady).Message, f.namespace+"/a-first")
	assert.Empty(t, f.authentik.takeWrites(), "a loser writes nothing to authentik")

	_, gotWinner, err := f.reconcile(t, winner)
	require.NoError(t, err)
	assertReady(t, gotWinner, metav1.ConditionTrue, v1alpha1.ReasonReconciled)

	// The loser stays a loser even after the winner has recorded a pk, and takes over once the winner is gone.
	_, got, err = f.reconcile(t, got)
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonConflict)

	require.NoError(t, k8sClient.Delete(t.Context(), gotWinner))
	waitForSlugIndex(t, slug, 1)
	_, got, err = f.reconcile(t, got)
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	application, err := f.authentik.GetApplication(t.Context(), slug)
	require.NoError(t, err)
	assert.Equal(t, application.Pk, got.Status.ApplicationPK, "the marked Application of the former winner is taken over")
}

// manualApplication creates an Application with a forward auth Proxy Provider and a Binding for admins in the
// fake, as if they had been created in the UI, and returns the Application.
func (f *fixture) manualApplication(t *testing.T, name, host string) *api.Application {
	t.Helper()
	ctx := t.Context()
	authorization, err := f.authentik.FindFlowsBySlug(ctx, authorizationSlug)
	require.NoError(t, err)
	invalidation, err := f.authentik.FindFlowsBySlug(ctx, invalidationSlug)
	require.NoError(t, err)
	provider, err := f.authentik.CreateProxyProvider(ctx, &api.ProxyProviderRequest{
		Name: "manual-" + f.slug, AuthorizationFlow: authorization[0].Pk, InvalidationFlow: invalidation[0].Pk,
		ExternalHost: host, Mode: new(api.PROXYMODE_FORWARD_SINGLE),
	})
	require.NoError(t, err)
	application, err := f.authentik.CreateApplication(ctx, &api.ApplicationRequest{
		Name: name, Slug: f.slug, Provider: *api.NewNullableInt32(&provider.Pk), MetaLaunchUrl: new(externalHost),
		PolicyEngineMode: new(api.POLICYENGINEMODE_ANY),
	})
	require.NoError(t, err)
	_, err = f.authentik.CreatePolicyBinding(ctx, &api.PolicyBindingRequest{
		Target: application.PbmUuid, Group: *api.NewNullableString(&f.admins.Pk), Order: 0,
	})
	require.NoError(t, err)
	f.authentik.takeWrites()
	return application
}

func (f *fixture) adoptSpec(policy v1alpha1.AdoptionPolicy) v1alpha1.AuthentikApplicationSpec {
	spec := f.proxySpec()
	spec.Adopt = new(policy)
	return spec
}

func TestReconcileAdoptsMatchingApplication(t *testing.T) {
	t.Parallel()

	for _, policy := range []v1alpha1.AdoptionPolicy{v1alpha1.AdoptionPolicyIfMatch, v1alpha1.AdoptionPolicyForce} {
		t.Run(string(policy), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			application := f.manualApplication(t, testName, externalHost)
			ctx := t.Context()
			// A second Binding that no rule matches stays unmanaged.
			legacy, err := f.authentik.CreatePolicyBinding(ctx, &api.PolicyBindingRequest{
				Target: application.PbmUuid, Group: *api.NewNullableString(new(f.authentik.AddGroup("legacy").Pk)), Order: 5,
			})
			require.NoError(t, err)
			f.authentik.takeWrites()

			_, got, err := f.reconcile(t, f.create(t, f.adoptSpec(policy)))
			require.NoError(t, err)
			assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
			assert.Equal(t, application.Pk, got.Status.ApplicationPK)
			assert.Equal(t, int64(*application.Provider.Get()), *got.Status.ProviderPK, "the attached Provider is adopted")
			assert.Empty(t, got.Status.AdoptionDiff)

			writes := f.authentik.takeWrites()
			assert.NotContains(t, writes, "CreateProxyProvider")
			assert.NotContains(t, writes, "PatchApplication")
			assert.NotContains(t, writes, "PatchProxyProvider")
			assert.Equal(t, 1, countOf(writes, opCreatePolicyBinding), "only the Binding for bob is created; the one for admins is adopted")

			bindings, err := f.authentik.ListPolicyBindings(ctx, application.PbmUuid)
			require.NoError(t, err)
			require.Len(t, bindings, 3)
			assert.NotContains(t, got.Status.BindingUUIDs, legacy.Pk)
			managed := f.managed(t)
			assert.Contains(t, managed, applicationObject(application))
			assert.NotContains(t, managed, bindingObject(legacy.Pk))
			assert.Contains(t, eventReasons(f.events()), "Normal Adopted")
		})
	}
}

func countOf(values []string, value string) int {
	count := 0
	for _, v := range values {
		if v == value {
			count++
		}
	}
	return count
}

func TestReconcileIfMatchReportsDiff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.manualApplication(t, "Manual", "https://manual.example.com")

	app := f.create(t, f.adoptSpec(v1alpha1.AdoptionPolicyIfMatch))
	result, got, err := f.reconcile(t, app)
	require.NoError(t, err)
	assert.Equal(t, resyncInterval, result.RequeueAfter)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonAdoptionDiff)
	assert.Equal(t, []v1alpha1.FieldDiff{
		{Field: "name", Desired: testName, Actual: "Manual"},
		{Field: "provider.proxy.forwardAuthSingle.externalHost", Desired: externalHost, Actual: "https://manual.example.com"},
	}, got.Status.AdoptionDiff)
	assert.Empty(t, f.authentik.takeWrites())
	assert.Empty(t, f.managed(t))

	// Switching to Force overwrites the differences and clears the diff.
	got.Spec.Adopt = new(v1alpha1.AdoptionPolicyForce)
	require.NoError(t, k8sClient.Update(t.Context(), got))
	_, adopted, err := f.reconcile(t, got)
	require.NoError(t, err)
	assertReady(t, adopted, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Empty(t, adopted.Status.AdoptionDiff)
	assert.Subset(t, f.authentik.takeWrites(), []string{"PatchApplication", "PatchProxyProvider"})

	application, err := f.authentik.GetApplication(t.Context(), f.slug)
	require.NoError(t, err)
	assert.Equal(t, testName, application.Name)
}

func TestReconcileAdoptionCreatesMissingProvider(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	application, err := f.authentik.CreateApplication(t.Context(), &api.ApplicationRequest{
		Name: testName, Slug: f.slug, MetaLaunchUrl: new(externalHost),
	})
	require.NoError(t, err)
	f.authentik.takeWrites()

	_, got, err := f.reconcile(t, f.create(t, f.adoptSpec(v1alpha1.AdoptionPolicyIfMatch)))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionTrue, v1alpha1.ReasonReconciled)
	assert.Contains(t, f.authentik.takeWrites(), "CreateProxyProvider")
	application, err = f.authentik.GetApplication(t.Context(), application.Slug)
	require.NoError(t, err)
	assert.Equal(t, new(int32(*got.Status.ProviderPK)), application.Provider.Get())
}

func TestReconcileAdoptionWithProviderTypeMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	flows, err := f.authentik.FindFlowsBySlug(ctx, authorizationSlug)
	require.NoError(t, err)
	provider, err := f.authentik.CreateOAuth2Provider(ctx, &api.OAuth2ProviderRequest{
		Name: "oauth2-" + f.slug, AuthorizationFlow: flows[0].Pk, InvalidationFlow: flows[0].Pk, RedirectUris: []api.RedirectURIRequest{},
	})
	require.NoError(t, err)
	_, err = f.authentik.CreateApplication(ctx, &api.ApplicationRequest{Name: testName, Slug: f.slug, Provider: *api.NewNullableInt32(&provider.Pk)})
	require.NoError(t, err)
	f.authentik.takeWrites()

	_, got, err := f.reconcile(t, f.create(t, f.adoptSpec(v1alpha1.AdoptionPolicyForce)))
	require.NoError(t, err)
	assertReady(t, got, metav1.ConditionFalse, v1alpha1.ReasonProviderTypeMismatch)
	assert.Empty(t, f.authentik.takeWrites())
	assert.Empty(t, f.managed(t), "nothing is marked when adoption fails")
	assert.Empty(t, got.Status.ApplicationPK)
}

func TestFieldDiffsRedactsConfidentialValues(t *testing.T) {
	t.Parallel()

	patch := &api.PatchedOAuth2ProviderRequest{ClientSecret: new("new-secret"), ClientId: new("new-id")}
	observed := &api.OAuth2Provider{ClientSecret: new("old-secret"), ClientId: new("old-id")}
	assert.Equal(t, []v1alpha1.FieldDiff{
		{Field: "provider.oauth2.credentials.clientID", Desired: "new-id", Actual: "old-id"},
		{Field: "provider.oauth2.credentials.secretRef.clientSecretKey", Desired: redacted, Actual: redacted},
	}, fieldDiffs(oauth2FieldPathsFor(), patch, observed))
}

// legacyBinding creates an unmanaged Binding for the group legacy on the Application of the fixture.
func (f *fixture) legacyBinding(t *testing.T) *api.PolicyBinding {
	t.Helper()
	application, err := f.authentik.GetApplication(t.Context(), f.slug)
	require.NoError(t, err)
	binding, err := f.authentik.CreatePolicyBinding(t.Context(), &api.PolicyBindingRequest{
		Target: application.PbmUuid, Group: *api.NewNullableString(new(f.authentik.AddGroup("legacy").Pk)), Order: 100,
	})
	require.NoError(t, err)
	f.authentik.takeWrites()
	f.events()
	return binding
}

func TestReconcileUnmanagedBindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		public bool
		prune  bool
		// wantReason is the reason of the Ready condition.
		wantReason        string
		wantCondition     bool
		wantKept          bool
		wantEventReasons  []string
		wantWritesInOrder []string
	}{
		{
			name:             "reported when prune is false",
			wantReason:       v1alpha1.ReasonReconciled,
			wantCondition:    true,
			wantKept:         true,
			wantEventReasons: []string{"Warning UnmanagedBindings"},
		},
		{
			name:              "deleted when prune is true",
			prune:             true,
			wantReason:        v1alpha1.ReasonReconciled,
			wantWritesInOrder: []string{opDeletePolicyBinding},
		},
		{
			name:             "public Application with unmanaged Bindings is not ready",
			public:           true,
			wantReason:       v1alpha1.ReasonUnmanagedBindings,
			wantKept:         true,
			wantEventReasons: []string{"Warning UnmanagedBindings"},
		},
		{
			name:              "public Application with prune loses every unmanaged Binding",
			public:            true,
			prune:             true,
			wantReason:        v1alpha1.ReasonReconciled,
			wantWritesInOrder: []string{opDeletePolicyBinding},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			spec := f.proxySpec()
			if tt.public {
				spec.Access.Rules = nil
				spec.Access.Public = new(true)
			}
			_, got, err := f.reconcile(t, f.create(t, spec))
			require.NoError(t, err)
			legacy := f.legacyBinding(t)

			got.Spec.Access.Prune = new(tt.prune)
			require.NoError(t, k8sClient.Update(t.Context(), got))
			_, got, err = f.reconcile(t, got)
			require.NoError(t, err)

			condition := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeReady)
			require.NotNil(t, condition)
			assert.Equal(t, tt.wantReason, condition.Reason, condition.Message)

			unmanaged := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionTypeUnmanagedBindings)
			if tt.wantCondition {
				require.NotNil(t, unmanaged)
				assert.Equal(t, metav1.ConditionTrue, unmanaged.Status)
				assert.Equal(t, "1 binding (group=legacy)", unmanaged.Message)
			} else {
				assert.Nil(t, unmanaged)
			}

			_, err = f.authentik.GetPolicyBinding(t.Context(), legacy.Pk)
			if tt.wantKept {
				require.NoError(t, err)
				assert.Equal(t, []v1alpha1.UnmanagedBinding{{UUID: legacy.Pk, Target: "group/legacy"}}, got.Status.UnmanagedBindings)
			} else {
				require.Error(t, err)
				assert.Empty(t, got.Status.UnmanagedBindings)
			}
			assert.ElementsMatch(t, tt.wantWritesInOrder, f.authentik.takeWrites())
			assert.ElementsMatch(t, tt.wantEventReasons, eventReasons(f.events()))
		})
	}
}

func TestReconcilePruneDeletesAfterWritingManagedBindings(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, got, err := f.reconcile(t, f.create(t, f.proxySpec()))
	require.NoError(t, err)
	f.legacyBinding(t)

	f.authentik.AddGroup("developers")
	got.Spec.Access.Prune = new(true)
	got.Spec.Access.Rules = append(got.Spec.Access.Rules, v1alpha1.AccessRule{Group: &v1alpha1.NamedReference{Name: new("developers")}})
	require.NoError(t, k8sClient.Update(t.Context(), got))

	_, _, err = f.reconcile(t, got)
	require.NoError(t, err)
	assert.Equal(t, []string{opCreatePolicyBinding, opAssignObjectPermission, opDeletePolicyBinding}, f.authentik.takeWrites())
}
