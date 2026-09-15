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
	"slices"

	api "goauthentik.io/api/v3"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
	"github.com/SlashNephy/authentik-operator/internal/ownership"
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

	managed, maxOrder, err := r.managedBindings(ctx, s, existing)
	if err != nil {
		return err
	}
	matched := r.matchBindings(s, managed)

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
	return r.patchStatus(ctx, s)
}

// managedBindings returns the Bindings that the operator manages, marked again when needed, and the largest order
// among all Bindings. A Binding is managed when its UUID is recorded in the status or it carries the marker.
func (r *AuthentikApplicationReconciler) managedBindings(ctx context.Context, s *reconcileState, existing []api.PolicyBinding) ([]*api.PolicyBinding, int32, error) {
	var managed []*api.PolicyBinding
	var maxOrder int32
	for i := range existing {
		binding := &existing[i]
		maxOrder = max(maxOrder, binding.Order)

		object := bindingObject(binding.Pk)
		if slices.Contains(s.app.Status.BindingUUIDs, binding.Pk) {
			if err := r.markers().ensure(ctx, object); err != nil {
				return nil, 0, err
			}
			managed = append(managed, binding)
			continue
		}
		marked, err := r.markers().contains(ctx, object)
		if err != nil {
			return nil, 0, err
		}
		if marked {
			managed = append(managed, binding)
		}
	}
	return managed, maxOrder, nil
}

// matchBindings assigns managed Bindings to rules by subject, preferring a Binding whose negate also matches.
// The result is indexed like the rules; a nil entry means that the rule needs a new Binding.
func (r *AuthentikApplicationReconciler) matchBindings(s *reconcileState, managed []*api.PolicyBinding) []*api.PolicyBinding {
	rules := s.resolved.Rules
	matched := make([]*api.PolicyBinding, len(rules))
	used := make(map[string]bool, len(managed))
	assign := func(exactNegate bool) {
		for i := range rules {
			if matched[i] != nil {
				continue
			}
			subject := ruleSubject(&rules[i])
			for _, binding := range managed {
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
	assign(false)
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
