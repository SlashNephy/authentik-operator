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
	"slices"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// reconcileOutpost ensures that the Proxy Provider is in the providers of its Outpost (docs/spec.md §3.7).
// The Outpost itself is not managed. The providers list is replaced as a whole with read-modify-write, which is
// safe against other reconciles because they are serialized.
func (r *AuthentikApplicationReconciler) reconcileOutpost(ctx context.Context, s *reconcileState, providerPK int32) error {
	uuid := s.resolved.Proxy.Outpost
	outpost, err := r.Authentik.GetOutpost(ctx, uuid)
	if err != nil {
		return err
	}
	if slices.Contains(outpost.Providers, providerPK) {
		return nil
	}
	if _, err := r.Authentik.SetOutpostProviders(ctx, uuid, append(slices.Clone(outpost.Providers), providerPK)); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Added Provider to Outpost", "outpost", outpost.Name, "provider", providerPK)
	return nil
}
