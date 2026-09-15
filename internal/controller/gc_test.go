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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/SlashNephy/authentik-operator/internal/ownership"
)

func TestMarkerCollectionRemovesMarkersOfDeletedObjects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, got, err := f.reconcile(t, f.create(t, f.proxySpec()))
	require.NoError(t, err)
	require.Len(t, f.managed(t), 4)

	// Deleting the Application in the UI also deletes its Bindings, but their markers remain.
	require.NoError(t, f.authentik.DeleteApplication(t.Context(), f.slug))
	require.Len(t, f.managed(t), 4)

	removed, err := f.reconciler.markers().collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 3, removed)
	assert.Equal(t, []ownership.Object{providerObject(ownership.ModelProxyProvider, got.Status.ProviderPK)}, f.managed(t))

	removed, err = f.reconciler.markers().collect(t.Context())
	require.NoError(t, err)
	assert.Zero(t, removed, "a second collection finds nothing")
}

func TestRoleRecreationRequeuesEveryResource(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Buffered, because the resources of other tests are sent as well and nobody receives them.
	events := make(chan event.GenericEvent, 1024)
	f.reconciler.roleEvents = events
	_, got, err := f.reconcile(t, f.create(t, f.proxySpec()))
	require.NoError(t, err)

	roles, err := f.authentik.FindRolesByName(t.Context(), testRole)
	require.NoError(t, err)
	f.authentik.DeleteRole(roles[0].Pk)
	_, err = f.reconciler.markers().collect(t.Context())
	require.NoError(t, err)

	// Every resource in the cluster is requeued, including those of other tests.
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Object.GetUID() == got.UID {
				return
			}
		case <-timeout:
			t.Fatal("the resource was not requeued after the role was recreated")
		}
	}
}
