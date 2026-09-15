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

// Package ownership records which authentik objects the operator manages with object permissions assigned to a
// dedicated role (docs/spec.md §3.1).
package ownership

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	api "goauthentik.io/api/v3"

	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

// roleNamePrefix prefixes the cluster name in the default role name.
const roleNamePrefix = "authentik-operator-"

// Models that carry the marker.
const (
	ModelApplication    = api.MODELENUM_AUTHENTIK_CORE_APPLICATION
	ModelProxyProvider  = api.MODELENUM_AUTHENTIK_PROVIDERS_PROXY_PROXYPROVIDER
	ModelOAuth2Provider = api.MODELENUM_AUTHENTIK_PROVIDERS_OAUTH2_OAUTH2PROVIDER
	ModelPolicyBinding  = api.MODELENUM_AUTHENTIK_POLICIES_POLICYBINDING
)

// RoleName returns the name of the ownership role. ownerRole takes precedence; otherwise the name is derived from
// clusterName. It fails when both are empty.
func RoleName(clusterName, ownerRole string) (string, error) {
	if ownerRole != "" {
		return ownerRole, nil
	}
	if clusterName == "" {
		return "", errors.New("either --cluster-name or --owner-role must be specified")
	}
	return roleNamePrefix + clusterName, nil
}

// Object identifies a marked authentik object.
type Object struct {
	Model api.ModelEnum
	// PK is the primary key as a string: the pk of an Application, the integer pk of a Provider, or the UUID of
	// a PolicyBinding.
	PK string
}

// viewPermission returns the view permission used as the marker of the model, such as
// authentik_core.view_application for authentik_core.application.
func viewPermission(model api.ModelEnum) string {
	appLabel, name, _ := strings.Cut(string(model), ".")
	return appLabel + ".view_" + name
}

// modelOf joins the app label and the model name of a permission into the model identifier.
func modelOf(appLabel, model string) api.ModelEnum {
	return api.ModelEnum(appLabel + "." + model)
}

// Marker attaches, removes, and looks up ownership markers. It is safe for concurrent use.
type Marker struct {
	client   authentik.RBACClient
	roleName string

	mu       sync.Mutex
	roleUUID string
}

// NewMarker returns a Marker that uses the role named roleName.
func NewMarker(client authentik.RBACClient, roleName string) *Marker {
	return &Marker{client: client, roleName: roleName}
}

// RoleName returns the name of the ownership role.
func (m *Marker) RoleName() string {
	return m.roleName
}

// EnsureRole looks up the ownership role by name, creates it when it does not exist, and remembers its UUID.
// It returns the UUID and the UUID that was remembered before the call, which is empty on the first call.
// A different previous UUID means that the role was deleted and recreated, and every marker was lost with it.
func (m *Marker) EnsureRole(ctx context.Context) (current, previous string, err error) {
	uuid, err := m.findOrCreateRole(ctx)
	if err != nil {
		return "", "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, m.roleUUID = m.roleUUID, uuid
	return uuid, previous, nil
}

func (m *Marker) findOrCreateRole(ctx context.Context) (string, error) {
	uuid, found, err := m.findRole(ctx)
	if err != nil || found {
		return uuid, err
	}
	role, createErr := m.client.CreateRole(ctx, m.roleName)
	if createErr == nil {
		return role.Pk, nil
	}
	// Another replica may have created the role concurrently, which makes the name collide.
	uuid, found, err = m.findRole(ctx)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("failed to create role %q: %w", m.roleName, createErr)
	}
	return uuid, nil
}

func (m *Marker) findRole(ctx context.Context) (uuid string, found bool, err error) {
	roles, err := m.client.FindRolesByName(ctx, m.roleName)
	if err != nil {
		return "", false, fmt.Errorf("failed to find role %q: %w", m.roleName, err)
	}
	switch len(roles) {
	case 0:
		return "", false, nil
	case 1:
		return roles[0].Pk, true, nil
	default:
		return "", false, fmt.Errorf("found %d roles named %q", len(roles), m.roleName)
	}
}

// role returns the remembered role UUID, ensuring the role first when none is remembered.
func (m *Marker) role(ctx context.Context) (string, error) {
	m.mu.Lock()
	uuid := m.roleUUID
	m.mu.Unlock()
	if uuid != "" {
		return uuid, nil
	}
	uuid, _, err := m.EnsureRole(ctx)
	return uuid, err
}

// Mark attaches the marker to the object. Marking an object that is already marked succeeds.
func (m *Marker) Mark(ctx context.Context, object Object) error {
	role, err := m.role(ctx)
	if err != nil {
		return err
	}
	if err := m.client.AssignObjectPermission(ctx, role, object.Model, object.PK, viewPermission(object.Model)); err != nil {
		return fmt.Errorf("failed to mark %s %s: %w", object.Model, object.PK, err)
	}
	return nil
}

// MarkIfExists attaches the marker to the object when the object exists and reports whether it exists. authentik
// validates the object when a permission is assigned, so this detects a deleted object without reading it.
// It is meant for objects that already carry the marker, for which assigning it again changes nothing.
func (m *Marker) MarkIfExists(ctx context.Context, object Object) (bool, error) {
	role, err := m.role(ctx)
	if err != nil {
		return false, err
	}
	err = m.client.AssignObjectPermission(ctx, role, object.Model, object.PK, viewPermission(object.Model))
	var apiErr *authentik.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(apiErr.Body, "object_pk") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to mark %s %s: %w", object.Model, object.PK, err)
	}
	return true, nil
}

// Unmark removes the marker from the object. Unmarking an object that is not marked succeeds.
func (m *Marker) Unmark(ctx context.Context, object Object) error {
	role, err := m.role(ctx)
	if err != nil {
		return err
	}
	if err := m.client.UnassignObjectPermission(ctx, role, object.Model, object.PK, viewPermission(object.Model)); err != nil {
		return fmt.Errorf("failed to unmark %s %s: %w", object.Model, object.PK, err)
	}
	return nil
}

// IsManaged reports whether the object carries the marker, using the owner lookup of the single object.
// The lookup returns other roles and every object permission of each role, so the result is narrowed to the
// ownership role and to the model and pk of the object (docs/spec.md §3.1).
func (m *Marker) IsManaged(ctx context.Context, object Object) (bool, error) {
	role, err := m.role(ctx)
	if err != nil {
		return false, err
	}
	assignments, err := m.client.ListObjectPermissionRoles(ctx, object.Model, object.PK)
	if err != nil {
		return false, fmt.Errorf("failed to look up the owner of %s %s: %w", object.Model, object.PK, err)
	}
	for _, assignment := range assignments {
		if assignment.RolePk != role {
			continue
		}
		for _, permission := range assignment.ObjectPermissions {
			if modelOf(permission.AppLabel, permission.Model) == object.Model && permission.ObjectPk == object.PK {
				return true, nil
			}
		}
	}
	return false, nil
}

// Set is the set of marked objects read at one point in time.
type Set struct {
	objects map[Object]struct{}
}

// Contains reports whether the object is in the set.
func (s *Set) Contains(object Object) bool {
	_, ok := s.objects[object]
	return ok
}

// Len returns the number of objects in the set.
func (s *Set) Len() int {
	return len(s.objects)
}

// Objects returns the objects in the set in no particular order.
func (s *Set) Objects() []Object {
	objects := make([]Object, 0, len(s.objects))
	for object := range s.objects {
		objects = append(objects, object)
	}
	return objects
}

// ListManaged returns every object that carries the marker. It reads the whole marker list in one request series
// and is meant to be called once per resync (docs/spec.md §3.1).
func (m *Marker) ListManaged(ctx context.Context) (*Set, error) {
	role, err := m.role(ctx)
	if err != nil {
		return nil, err
	}
	permissions, err := m.client.ListRoleObjectPermissions(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("failed to list the markers of role %q: %w", m.roleName, err)
	}
	set := &Set{objects: make(map[Object]struct{}, len(permissions))}
	for _, permission := range permissions {
		set.objects[Object{Model: modelOf(permission.AppLabel, permission.Model), PK: permission.ObjectPk}] = struct{}{}
	}
	return set, nil
}
