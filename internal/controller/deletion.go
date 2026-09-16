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
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	api "goauthentik.io/api/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

// finalizer keeps a resource until its objects in authentik are released (docs/spec.md §3.8).
const finalizer = "authentik.starry.blue/finalizer"

// ensureFinalizer adds the finalizer before anything is written to authentik.
func (r *AuthentikApplicationReconciler) ensureFinalizer(ctx context.Context, app *v1alpha1.AuthentikApplication) error {
	base := app.DeepCopy()
	if !controllerutil.AddFinalizer(app, finalizer) {
		return nil
	}
	if err := r.Patch(ctx, app, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("failed to add the finalizer: %w", err)
	}
	return nil
}

// finalize releases the objects recorded in the status according to spec.deletionPolicy and removes the finalizer.
// While authentik cannot be reached, the finalizer is kept and the release is retried.
func (r *AuthentikApplicationReconciler) finalize(ctx context.Context, app *v1alpha1.AuthentikApplication) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(app, finalizer) {
		return ctrl.Result{}, nil
	}

	if err := r.release(ctx, app); err != nil {
		s := &reconcileState{app: app, base: app.DeepCopy()}
		s.app.Status.ObservedGeneration = s.app.Generation
		r.setReady(s, metav1.ConditionFalse, v1alpha1.ReasonAPIError, "Failed to release the objects in authentik: "+err.Error())
		return ctrl.Result{}, errors.Join(err, r.patchStatus(ctx, s))
	}

	base := app.DeepCopy()
	controllerutil.RemoveFinalizer(app, finalizer)
	if err := r.Patch(ctx, app, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("failed to remove the finalizer: %w", err))
	}
	return ctrl.Result{}, nil
}

// release deletes the managed objects when deletionPolicy is Delete, and removes their markers in both modes.
// Objects that no longer exist count as released.
func (r *AuthentikApplicationReconciler) release(ctx context.Context, app *v1alpha1.AuthentikApplication) error {
	status := &app.Status
	remove := app.Spec.DeletionPolicy != nil && *app.Spec.DeletionPolicy == v1alpha1.DeletionPolicyDelete

	var markers []ownership.Object
	for _, uuid := range status.BindingUUIDs {
		if remove {
			if err := ignoreNotFound(r.Authentik.DeletePolicyBinding(ctx, uuid)); err != nil {
				return err
			}
		}
		markers = append(markers, bindingObject(uuid))
	}

	if status.ApplicationPK != "" {
		if remove {
			if err := r.deleteApplication(ctx, app); err != nil {
				return err
			}
		}
		markers = append(markers, ownership.Object{Model: ownership.ModelApplication, PK: status.ApplicationPK})
	}

	if status.ProviderPK != nil && app.Spec.Provider != nil {
		pk := int32(*status.ProviderPK)
		model := ownership.ModelOAuth2Provider
		if app.Spec.Provider.Proxy != nil {
			model = ownership.ModelProxyProvider
		}
		if remove {
			if err := r.deleteProvider(ctx, app, pk); err != nil {
				return err
			}
		}
		markers = append(markers, ownership.Object{Model: model, PK: strconv.Itoa(int(pk))})
	}

	for _, object := range markers {
		if err := r.markers().remove(ctx, object); err != nil {
			return err
		}
	}
	if remove {
		r.Recorder.Eventf(app, nil, corev1.EventTypeNormal, "Deleted", "Delete", "Deleted the objects in authentik")
	}
	logf.FromContext(ctx).Info("Released the objects in authentik", "delete", remove, "markers", len(markers))
	return nil
}

// deleteApplication deletes the recorded Application unless the slug now belongs to another Application.
func (r *AuthentikApplicationReconciler) deleteApplication(ctx context.Context, app *v1alpha1.AuthentikApplication) error {
	slug := cmp.Or(app.Status.ApplicationSlug, app.Spec.Slug)
	observed, err := r.Authentik.GetApplication(ctx, slug)
	if errors.Is(err, authentik.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if observed.Pk != app.Status.ApplicationPK {
		return nil
	}
	return ignoreNotFound(r.Authentik.DeleteApplication(ctx, slug))
}

// deleteProvider removes a Proxy Provider from its Outpost and deletes the Provider.
func (r *AuthentikApplicationReconciler) deleteProvider(ctx context.Context, app *v1alpha1.AuthentikApplication, pk int32) error {
	if proxy := app.Spec.Provider.Proxy; proxy != nil {
		if err := r.leaveOutpost(ctx, proxy.Outpost, pk); err != nil {
			return err
		}
		return ignoreNotFound(r.Authentik.DeleteProxyProvider(ctx, pk))
	}
	return ignoreNotFound(r.Authentik.DeleteOAuth2Provider(ctx, pk))
}

// leaveOutpost removes the Provider from the providers of the Outpost. An Outpost that cannot be found is skipped,
// because deleting the Provider also detaches it from every Outpost.
func (r *AuthentikApplicationReconciler) leaveOutpost(ctx context.Context, ref *v1alpha1.NamedReference, pk int32) error {
	ref = cmp.Or(ref, &v1alpha1.NamedReference{Name: new(reference.EmbeddedOutpostName)})
	var outpost *api.Outpost
	if ref.UUID != nil {
		found, err := r.Authentik.GetOutpost(ctx, *ref.UUID)
		if err != nil {
			return ignoreNotFound(err)
		}
		outpost = found
	} else {
		found, err := r.Authentik.FindOutpostsByName(ctx, *ref.Name)
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return nil
		}
		outpost = &found[0]
	}
	return r.removeProviderFromOutpost(ctx, outpost, pk)
}

// leaveOutpostByUUID removes the Provider from the providers of the Outpost with the UUID. An Outpost that no
// longer exists is skipped.
func (r *AuthentikApplicationReconciler) leaveOutpostByUUID(ctx context.Context, uuid string, pk int32) error {
	outpost, err := r.Authentik.GetOutpost(ctx, uuid)
	if err != nil {
		return ignoreNotFound(err)
	}
	return r.removeProviderFromOutpost(ctx, outpost, pk)
}

// removeProviderFromOutpost writes back the providers of the Outpost without the Provider.
func (r *AuthentikApplicationReconciler) removeProviderFromOutpost(ctx context.Context, outpost *api.Outpost, pk int32) error {
	if !slices.Contains(outpost.Providers, pk) {
		return nil
	}
	providers := slices.DeleteFunc(slices.Clone(outpost.Providers), func(p int32) bool { return p == pk })
	_, err := r.Authentik.SetOutpostProviders(ctx, outpost.Pk, providers)
	return ignoreNotFound(err)
}

func ignoreNotFound(err error) error {
	if errors.Is(err, authentik.ErrNotFound) {
		return nil
	}
	return err
}
