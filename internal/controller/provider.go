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
	"errors"
	"strconv"

	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
)

// observedProvider is a fetched Provider of either type.
type observedProvider struct {
	pk int32
	// assignedApplication is the slug of the Application that uses the Provider, or nil.
	assignedApplication *string
	// sync patches the managed fields that differ from the fetched Provider.
	sync func(ctx context.Context) error
	// diffs lists the managed fields that differ from the fetched Provider, for adoption diffs.
	diffs func() []v1alpha1.FieldDiff
}

// providerHandler performs the operations that depend on the Provider type.
type providerHandler interface {
	kind() string
	model() api.ModelEnum
	get(ctx context.Context, pk int32) (*observedProvider, error)
	findByName(ctx context.Context, name string) ([]*observedProvider, error)
	create(ctx context.Context, name string) (int32, error)
	// existsAsOtherType reports whether a Provider of the other type has the pk.
	existsAsOtherType(ctx context.Context, pk int32) (bool, error)
}

func (r *AuthentikApplicationReconciler) providerHandler(s *reconcileState) providerHandler {
	provider := s.app.Spec.Provider
	if provider.Proxy != nil {
		return &proxyProviderHandler{
			client:  r.Authentik,
			spec:    provider.Proxy,
			desired: desiredProxyProvider(provider, s.resolved.Flows, s.resolved.Proxy),
		}
	}
	return &oauth2ProviderHandler{
		reconciler: r,
		app:        s.app,
		desired:    desiredOAuth2Provider(provider, s.resolved.Flows, s.resolved.OAuth2),
	}
}

// reconcileProvider finds, creates, or repairs the Provider, and returns its pk (docs/spec.md §3.3).
func (r *AuthentikApplicationReconciler) reconcileProvider(ctx context.Context, s *reconcileState, application *api.Application) (*int32, error) {
	handler := r.providerHandler(s)
	provider, err := r.findProvider(ctx, s, handler, application)
	if err != nil {
		return nil, err
	}

	created := provider == nil
	var pk int32
	if created {
		name := providerName(&s.app.Spec)
		if pk, err = handler.create(ctx, name); err != nil {
			return nil, err
		}
		r.Recorder.Eventf(s.app, nil, corev1.EventTypeNormal, eventReasonCreated, eventActionReconcile, "Created %s Provider %q", handler.kind(), name)
	} else {
		pk = provider.pk
	}

	// Record the pk before attaching the marker; see reconcileApplication.
	if recorded := s.app.Status.ProviderPK; recorded == nil || *recorded != int64(pk) {
		s.app.Status.ProviderPK = new(int64(pk))
		if err := r.patchStatus(ctx, s); err != nil {
			return nil, err
		}
	}
	if err := r.markers().ensure(ctx, ownership.Object{Model: handler.model(), PK: strconv.Itoa(int(pk))}); err != nil {
		return nil, err
	}
	if !created {
		if err := provider.sync(ctx); err != nil {
			return nil, err
		}
	}
	return &pk, nil
}

// findProvider returns the Provider to reconcile, or nil when it has to be created. It tries, in order, the pk
// recorded in the status, the Provider attached to the Application, and a Provider with the name that no other
// Application uses, which recovers from a crash between creating the Provider and recording it.
func (r *AuthentikApplicationReconciler) findProvider(ctx context.Context, s *reconcileState, handler providerHandler, application *api.Application) (*observedProvider, error) {
	status := &s.app.Status
	if status.ProviderPK != nil {
		pk := int32(*status.ProviderPK)
		provider, err := handler.get(ctx, pk)
		if !errors.Is(err, authentik.ErrNotFound) {
			return provider, err
		}
		r.Recorder.Eventf(s.app, nil, corev1.EventTypeWarning, eventReasonRecreated, eventActionReconcile,
			"%s Provider %d was deleted outside the operator and is recreated", handler.kind(), pk)
		status.ProviderPK = nil
	}

	if application != nil && application.Provider.Get() != nil {
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
	}

	candidates, err := handler.findByName(ctx, providerName(&s.app.Spec))
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if candidate.assignedApplication == nil || *candidate.assignedApplication == s.app.Spec.Slug {
			logf.FromContext(ctx).Info("Reusing Provider without an Application", "kind", handler.kind(), "pk", candidate.pk)
			return candidate, nil
		}
	}
	return nil, nil
}

type proxyProviderHandler struct {
	client  authentik.Client
	spec    *v1alpha1.ProxyProviderSpec
	desired *api.PatchedProxyProviderRequest
}

var _ providerHandler = new(proxyProviderHandler)

func (*proxyProviderHandler) kind() string { return "Proxy" }

func (*proxyProviderHandler) model() api.ModelEnum { return ownership.ModelProxyProvider }

func (h *proxyProviderHandler) observe(provider *api.ProxyProvider) *observedProvider {
	return &observedProvider{
		pk:                  provider.Pk,
		assignedApplication: provider.AssignedApplicationSlug.Get(),
		sync: func(ctx context.Context) error {
			patch, changed := authentik.DiffProxyProvider(h.desired, provider)
			if !changed {
				return nil
			}
			if _, err := h.client.PatchProxyProvider(ctx, provider.Pk, patch); err != nil {
				return err
			}
			logf.FromContext(ctx).Info("Updated Proxy Provider", "pk", provider.Pk)
			return nil
		},
		diffs: func() []v1alpha1.FieldDiff {
			patch, changed := authentik.DiffProxyProvider(h.desired, provider)
			if !changed {
				return nil
			}
			return fieldDiffs(proxyFieldPathsFor(h.spec), patch, provider)
		},
	}
}

func (h *proxyProviderHandler) get(ctx context.Context, pk int32) (*observedProvider, error) {
	provider, err := h.client.GetProxyProvider(ctx, pk)
	if err != nil {
		return nil, err
	}
	return h.observe(provider), nil
}

func (h *proxyProviderHandler) findByName(ctx context.Context, name string) ([]*observedProvider, error) {
	providers, err := h.client.FindProxyProvidersByName(ctx, name)
	if err != nil {
		return nil, err
	}
	observed := make([]*observedProvider, 0, len(providers))
	for i := range providers {
		observed = append(observed, h.observe(&providers[i]))
	}
	return observed, nil
}

func (h *proxyProviderHandler) create(ctx context.Context, name string) (int32, error) {
	provider, err := h.client.CreateProxyProvider(ctx, createProxyProviderRequest(name, h.desired))
	if err != nil {
		return 0, err
	}
	return provider.Pk, nil
}

func (h *proxyProviderHandler) existsAsOtherType(ctx context.Context, pk int32) (bool, error) {
	return exists(h.client.GetOAuth2Provider(ctx, pk))
}

type oauth2ProviderHandler struct {
	reconciler *AuthentikApplicationReconciler
	app        *v1alpha1.AuthentikApplication
	desired    *api.PatchedOAuth2ProviderRequest
}

var _ providerHandler = new(oauth2ProviderHandler)

func (*oauth2ProviderHandler) kind() string { return "OAuth2" }

func (*oauth2ProviderHandler) model() api.ModelEnum { return ownership.ModelOAuth2Provider }

func (h *oauth2ProviderHandler) observe(provider *api.OAuth2Provider) *observedProvider {
	return &observedProvider{
		pk:                  provider.Pk,
		assignedApplication: provider.AssignedApplicationSlug.Get(),
		sync: func(ctx context.Context) error {
			patch, changed := authentik.DiffOAuth2Provider(h.desired, provider)
			if !changed {
				return nil
			}
			if _, err := h.reconciler.Authentik.PatchOAuth2Provider(ctx, provider.Pk, patch); err != nil {
				return err
			}
			logf.FromContext(ctx).Info("Updated OAuth2 Provider", "pk", provider.Pk)
			return nil
		},
		diffs: func() []v1alpha1.FieldDiff {
			patch, changed := authentik.DiffOAuth2Provider(h.desired, provider)
			if !changed {
				return nil
			}
			return fieldDiffs(oauth2FieldPathsFor(), patch, provider)
		},
	}
}

func (h *oauth2ProviderHandler) get(ctx context.Context, pk int32) (*observedProvider, error) {
	provider, err := h.reconciler.Authentik.GetOAuth2Provider(ctx, pk)
	if err != nil {
		return nil, err
	}
	return h.observe(provider), nil
}

func (h *oauth2ProviderHandler) findByName(ctx context.Context, name string) ([]*observedProvider, error) {
	providers, err := h.reconciler.Authentik.FindOAuth2ProvidersByName(ctx, name)
	if err != nil {
		return nil, err
	}
	observed := make([]*observedProvider, 0, len(providers))
	for i := range providers {
		observed = append(observed, h.observe(&providers[i]))
	}
	return observed, nil
}

func (h *oauth2ProviderHandler) create(ctx context.Context, name string) (int32, error) {
	defaults, err := h.reconciler.Resolver.ResolveCreationDefaults(ctx, h.app)
	if err != nil {
		return 0, err
	}
	provider, err := h.reconciler.Authentik.CreateOAuth2Provider(ctx, createOAuth2ProviderRequest(name, h.desired, defaults))
	if err != nil {
		return 0, err
	}
	return provider.Pk, nil
}

func (h *oauth2ProviderHandler) existsAsOtherType(ctx context.Context, pk int32) (bool, error) {
	return exists(h.reconciler.Authentik.GetProxyProvider(ctx, pk))
}

// exists converts the result of a Get call into whether the object exists.
func exists[T any](_ *T, err error) (bool, error) {
	if errors.Is(err, authentik.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
