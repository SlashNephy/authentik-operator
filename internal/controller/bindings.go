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
	"fmt"
	"slices"
	"strconv"
	"strings"

	api "goauthentik.io/api/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

// Kinds of Binding subjects used in status.unmanagedBindings.
const (
	subjectKindGroup  = "group"
	subjectKindUser   = "user"
	subjectKindPolicy = "policy"
)

// orderStep is the gap between the order of a new Binding and the largest existing order (docs/spec.md §2.4).
const orderStep = 10

func bindingObject(uuid string) ownership.Object {
	return ownership.Object{Model: ownership.ModelPolicyBinding, PK: uuid}
}

// reconcileBindings creates and repairs the managed Bindings of the rules, and deletes managed Bindings that no
// rule needs any more. Deletion happens after every write, so that the Application never has fewer Bindings than
// the rules require (docs/spec.md §3.5).
func (r *AuthentikApplicationReconciler) reconcileBindings(ctx context.Context, s *reconcileState, application *api.Application) error {
	target := application.PbmUuid
	existing, err := r.Authentik.ListPolicyBindings(ctx, target)
	if err != nil {
		return err
	}

	managed, unmanaged, maxOrder, err := r.managedBindings(ctx, s, existing)
	if err != nil {
		return err
	}
	matched := matchBindings(s.resolved.Rules, managed, false)
	if len(s.app.Status.BindingUUIDs) == 0 {
		// No Binding has been recorded yet, as right after adoption: existing Bindings whose subject and negate
		// match a rule are adopted (docs/spec.md §3.4).
		for i, binding := range matchBindings(s.resolved.Rules, unmanaged, true) {
			if matched[i] != nil || binding == nil {
				continue
			}
			if err := r.markers().ensure(ctx, bindingObject(binding.Pk)); err != nil {
				return err
			}
			matched[i] = binding
			logf.FromContext(ctx).Info("Adopted PolicyBinding", "uuid", binding.Pk)
		}
	}

	kept := make([]string, 0, len(s.resolved.Rules))
	for i := range s.resolved.Rules {
		desired := desiredBinding(target, &s.resolved.Rules[i])
		if binding := matched[i]; binding != nil {
			if err := r.syncBinding(ctx, desired, binding); err != nil {
				return err
			}
			kept = append(kept, binding.Pk)
			continue
		}

		maxOrder += orderStep
		created, err := r.Authentik.CreatePolicyBinding(ctx, createBindingRequest(desired, maxOrder))
		if err != nil {
			return err
		}
		kept = append(kept, created.Pk)
		// Record the UUID before attaching the marker; see reconcileApplication.
		s.app.Status.BindingUUIDs = union(s.app.Status.BindingUUIDs, created.Pk)
		if err := r.patchStatus(ctx, s); err != nil {
			return err
		}
		if err := r.markers().ensure(ctx, bindingObject(created.Pk)); err != nil {
			return err
		}
		logf.FromContext(ctx).Info("Created PolicyBinding", "uuid", created.Pk, "order", created.Order)
	}

	for _, binding := range managed {
		if slices.Contains(kept, binding.Pk) {
			continue
		}
		if err := r.deleteBinding(ctx, binding.Pk); err != nil {
			return err
		}
	}
	s.app.Status.BindingUUIDs = kept
	if err := r.patchStatus(ctx, s); err != nil {
		return err
	}

	remaining := slices.DeleteFunc(unmanaged, func(binding *api.PolicyBinding) bool { return slices.Contains(kept, binding.Pk) })
	return r.handleUnmanagedBindings(ctx, s, remaining)
}

// handleUnmanagedBindings deletes the unmanaged Bindings when prune is true, and otherwise reports them
// (docs/spec.md §3.5). It runs after every managed Binding has been written.
func (r *AuthentikApplicationReconciler) handleUnmanagedBindings(ctx context.Context, s *reconcileState, unmanaged []*api.PolicyBinding) error {
	access := &s.app.Spec.Access
	if access.Prune != nil && *access.Prune {
		for _, binding := range unmanaged {
			if err := r.Authentik.DeletePolicyBinding(ctx, binding.Pk); err != nil && !errors.Is(err, authentik.ErrNotFound) {
				return err
			}
			logf.FromContext(ctx).Info("Deleted unmanaged PolicyBinding", "uuid", binding.Pk)
		}
		unmanaged = nil
	}

	reported := make([]v1alpha1.UnmanagedBinding, 0, len(unmanaged))
	for _, binding := range unmanaged {
		target, err := r.describeSubject(ctx, binding)
		if err != nil {
			return err
		}
		reported = append(reported, v1alpha1.UnmanagedBinding{UUID: binding.Pk, Target: target})
	}
	s.app.Status.UnmanagedBindings = nil
	if len(reported) > 0 {
		s.app.Status.UnmanagedBindings = reported
	}

	public := access.Public != nil && *access.Public
	message := unmanagedBindingsMessage(reported)
	switch {
	case len(reported) == 0:
		meta.RemoveStatusCondition(&s.app.Status.Conditions, v1alpha1.ConditionTypeUnmanagedBindings)
	case public:
		// The Application cannot become public while Bindings remain, so this is not only a warning.
		meta.RemoveStatusCondition(&s.app.Status.Conditions, v1alpha1.ConditionTypeUnmanagedBindings)
		return &stopError{
			reason:  v1alpha1.ReasonUnmanagedBindings,
			message: message + " keep the Application from being public; set access.prune or delete them",
		}
	default:
		r.setCondition(s, v1alpha1.ConditionTypeUnmanagedBindings, metav1.ConditionTrue, v1alpha1.ReasonUnmanagedBindings, message)
	}
	return nil
}

// unmanagedBindingsMessage summarizes unmanaged Bindings, such as "1 binding (group=legacy)".
func unmanagedBindingsMessage(bindings []v1alpha1.UnmanagedBinding) string {
	targets := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		targets = append(targets, strings.Replace(binding.Target, "/", "=", 1))
	}
	noun := "bindings"
	if len(bindings) == 1 {
		noun = "binding"
	}
	return fmt.Sprintf("%d %s (%s)", len(bindings), noun, strings.Join(targets, ", "))
}

// describeSubject describes the subject of a Binding, such as group/legacy. A subject that no longer exists is
// described by its identifier.
func (r *AuthentikApplicationReconciler) describeSubject(ctx context.Context, binding *api.PolicyBinding) (string, error) {
	subject := observedSubject(binding)
	var kind, name, id string
	var err error
	switch {
	case subject.group != "":
		kind, id = subjectKindGroup, subject.group
		var group *api.Group
		if group, err = r.Authentik.GetGroup(ctx, subject.group); err == nil {
			name = group.Name
		}
	case subject.policy != "":
		kind, id = subjectKindPolicy, subject.policy
		var policy *api.Policy
		if policy, err = r.Authentik.GetPolicy(ctx, subject.policy); err == nil {
			name = policy.Name
		}
	default:
		kind, id = subjectKindUser, strconv.Itoa(int(subject.user))
		var user *api.User
		if user, err = r.Authentik.GetUser(ctx, subject.user); err == nil {
			name = user.Username
		}
	}
	if errors.Is(err, authentik.ErrNotFound) {
		return kind + "/" + id, nil
	}
	if err != nil {
		return "", err
	}
	return kind + "/" + name, nil
}

// managedBindings splits the Bindings into those that the operator manages, marked again when needed, and the
// others, and returns the largest order among all Bindings. A Binding is managed when its UUID is recorded in the
// status or it carries the marker.
func (r *AuthentikApplicationReconciler) managedBindings(ctx context.Context, s *reconcileState, existing []api.PolicyBinding) (managed, unmanaged []*api.PolicyBinding, maxOrder int32, err error) {
	for i := range existing {
		binding := &existing[i]
		maxOrder = max(maxOrder, binding.Order)

		object := bindingObject(binding.Pk)
		if slices.Contains(s.app.Status.BindingUUIDs, binding.Pk) {
			if err := r.markers().ensure(ctx, object); err != nil {
				return nil, nil, 0, err
			}
			managed = append(managed, binding)
			continue
		}
		marked, err := r.markers().contains(ctx, object)
		if err != nil {
			return nil, nil, 0, err
		}
		if marked {
			managed = append(managed, binding)
		} else {
			unmanaged = append(unmanaged, binding)
		}
	}
	return managed, unmanaged, maxOrder, nil
}

// matchBindings assigns Bindings to rules by subject, preferring a Binding whose negate also matches. When
// exactOnly is true, a Binding with a different negate is never assigned. The result is indexed like the rules;
// a nil entry means that no Binding was assigned to the rule.
func matchBindings(rules []reference.Rule, bindings []*api.PolicyBinding, exactOnly bool) []*api.PolicyBinding {
	matched := make([]*api.PolicyBinding, len(rules))
	used := make(map[string]bool, len(bindings))
	assign := func(exactNegate bool) {
		for i := range rules {
			if matched[i] != nil {
				continue
			}
			subject := ruleSubject(&rules[i])
			for _, binding := range bindings {
				negate := binding.Negate != nil && *binding.Negate
				if used[binding.Pk] || observedSubject(binding) != subject || (exactNegate && negate != rules[i].Negate) {
					continue
				}
				matched[i] = binding
				used[binding.Pk] = true
				break
			}
		}
	}
	assign(true)
	if !exactOnly {
		assign(false)
	}
	return matched
}

func (r *AuthentikApplicationReconciler) syncBinding(ctx context.Context, desired *api.PatchedPolicyBindingRequest, binding *api.PolicyBinding) error {
	patch, changed := authentik.DiffPolicyBinding(desired, binding)
	if !changed {
		return nil
	}
	if _, err := r.Authentik.PatchPolicyBinding(ctx, binding.Pk, patch); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Updated PolicyBinding", "uuid", binding.Pk)
	return nil
}

// deleteBinding deletes a managed Binding and its marker. A Binding that is already gone counts as deleted.
func (r *AuthentikApplicationReconciler) deleteBinding(ctx context.Context, uuid string) error {
	if err := r.Authentik.DeletePolicyBinding(ctx, uuid); err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return err
	}
	if err := r.markers().remove(ctx, bindingObject(uuid)); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Deleted PolicyBinding", "uuid", uuid)
	return nil
}

// union returns values with value appended unless it is already present.
func union(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(slices.Clone(values), value)
}
