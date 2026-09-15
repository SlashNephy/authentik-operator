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

// Package controller reconciles AuthentikApplications with authentik (docs/spec.md §3).
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
	"github.com/SlashNephy/authentik-operator/internal/reference"
	"github.com/SlashNephy/authentik-operator/internal/retry"
)

// Event reasons other than the reasons of the Ready condition.
const (
	eventReasonCreated   = "Created"
	eventReasonRecreated = "Recreated"
	eventActionReconcile = "Reconcile"
)

// AuthentikApplicationReconciler reconciles an AuthentikApplication object
type AuthentikApplicationReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Authentik authentik.Client
	Marker    *ownership.Marker
	Resolver  *reference.Resolver
	Recorder  events.EventRecorder
	// ResyncInterval is the period of drift detection and the upper bound of the retry interval.
	ResyncInterval time.Duration

	markersOnce sync.Once
	markerList  *markerCache
}

// +kubebuilder:rbac:groups=authentik.starry.blue,resources=authentikapplications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authentik.starry.blue,resources=authentikapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik.starry.blue,resources=authentikapplications/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// reconcileState carries one reconcile of an AuthentikApplication.
type reconcileState struct {
	app *v1alpha1.AuthentikApplication
	// base is the object as last written, used to compute status patches.
	base     *v1alpha1.AuthentikApplication
	resolved *reference.Resolved
}

// stopError stops a reconcile without writing to authentik and reports the reason in the Ready condition.
// The resource is checked again at the resync interval instead of being retried with backoff.
type stopError struct {
	reason  string
	message string
}

func (e *stopError) Error() string {
	return e.message
}

// Reconcile brings the Application, the Provider, and the Bindings in authentik to the state in the spec.
func (r *AuthentikApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	app := &v1alpha1.AuthentikApplication{}
	if err := r.Get(ctx, req.NamespacedName, app); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !app.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	s := &reconcileState{app: app, base: app.DeepCopy()}
	return r.finish(ctx, s, r.reconcile(ctx, s))
}

func (r *AuthentikApplicationReconciler) reconcile(ctx context.Context, s *reconcileState) error {
	if err := r.checkConflict(ctx, s); err != nil {
		return err
	}
	resolved, err := r.Resolver.Resolve(ctx, s.app)
	if err != nil {
		return err
	}
	s.resolved = resolved

	observed, err := r.observeApplication(ctx, s)
	if err != nil {
		return err
	}
	var providerPK *int32
	if s.app.Spec.Provider != nil {
		if providerPK, err = r.reconcileProvider(ctx, s, observed); err != nil {
			return err
		}
	}
	application, err := r.reconcileApplication(ctx, s, observed, providerPK)
	if err != nil {
		return err
	}
	return r.reconcileBindings(ctx, s, application)
}

// finish records the outcome in the status and decides how the resource is requeued.
func (r *AuthentikApplicationReconciler) finish(ctx context.Context, s *reconcileState, err error) (ctrl.Result, error) {
	s.app.Status.ObservedGeneration = s.app.Generation

	var stop *stopError
	var refErr *reference.Error
	switch {
	case err == nil:
		s.app.Status.LastAppliedHash = specHash(&s.app.Spec)
		r.setReady(s, metav1.ConditionTrue, v1alpha1.ReasonReconciled, "The Application, the Provider, and the Bindings match the spec")
	case errors.As(err, &stop):
		r.setReady(s, metav1.ConditionFalse, stop.reason, stop.message)
	case errors.As(err, &refErr):
		r.setReady(s, metav1.ConditionFalse, refErr.Reason(), refErr.Error())
	default:
		r.setReady(s, metav1.ConditionFalse, v1alpha1.ReasonAPIError, err.Error())
	}

	if patchErr := r.patchStatus(ctx, s); patchErr != nil {
		return ctrl.Result{}, errors.Join(err, patchErr)
	}
	if err == nil || stop != nil {
		return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
	}
	// The rate limiter retries with exponential backoff capped at the resync interval (docs/spec.md §3.6).
	return ctrl.Result{}, err
}

// setReady sets the Ready condition and records an Event when its status or reason changes.
func (r *AuthentikApplicationReconciler) setReady(s *reconcileState, status metav1.ConditionStatus, reason, message string) {
	previous := meta.FindStatusCondition(s.app.Status.Conditions, v1alpha1.ConditionTypeReady)
	changed := previous == nil || previous.Status != status || previous.Reason != reason
	meta.SetStatusCondition(&s.app.Status.Conditions, metav1.Condition{
		Type:               v1alpha1.ConditionTypeReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.app.Generation,
	})
	if !changed {
		return
	}
	eventType := corev1.EventTypeNormal
	if status != metav1.ConditionTrue {
		eventType = corev1.EventTypeWarning
	}
	r.Recorder.Eventf(s.app, nil, eventType, reason, eventActionReconcile, "%s", message)
}

// patchStatus writes the status when it differs from the last written one.
func (r *AuthentikApplicationReconciler) patchStatus(ctx context.Context, s *reconcileState) error {
	if equality.Semantic.DeepEqual(s.base.Status, s.app.Status) {
		return nil
	}
	if err := r.Status().Patch(ctx, s.app, client.MergeFrom(s.base)); err != nil {
		return fmt.Errorf("failed to update the status: %w", err)
	}
	s.base = s.app.DeepCopy()
	return nil
}

// markers returns the marker cache shared by every reconcile.
func (r *AuthentikApplicationReconciler) markers() *markerCache {
	r.markersOnce.Do(func() {
		r.markerList = newMarkerCache(r.Marker, r.ResyncInterval)
	})
	return r.markerList
}

// specHash returns the hash of the spec recorded as lastAppliedHash.
func specHash(spec *v1alpha1.AuthentikApplicationSpec) string {
	// Marshaling a struct of plain fields cannot fail.
	data, _ := json.Marshal(spec)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthentikApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := IndexSlug(context.Background(), mgr.GetFieldIndexer()); err != nil {
		return fmt.Errorf("failed to index %s: %w", slugIndexField, err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// Status writes do not change the generation, so they do not trigger another reconcile.
		For(&v1alpha1.AuthentikApplication{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1alpha1.AuthentikApplication{}, handler.EnqueueRequestsFromMapFunc(r.sameSlugRequests),
			builder.WithPredicates(conflictPredicate)).
		Named("authentikapplication").
		WithOptions(controller.Options{
			// Outpost membership is updated with read-modify-write, so reconciles are serialized (docs/spec.md §3.7).
			MaxConcurrentReconciles: 1,
			RateLimiter:             retry.NewRateLimiter[reconcile.Request](r.ResyncInterval),
		}).
		Complete(r)
}
