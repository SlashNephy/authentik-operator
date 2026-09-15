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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/reference"
)

// credentialsSecretIndexField indexes resources by the name of their credentials Secret (docs/spec.md §2.5).
const credentialsSecretIndexField = "spec.provider.oauth2.credentials.secretRef.name"

// IndexCredentialsSecret registers the field index of the credentials Secret name.
func IndexCredentialsSecret(ctx context.Context, indexer client.FieldIndexer) error {
	return indexer.IndexField(ctx, &v1alpha1.AuthentikApplication{}, credentialsSecretIndexField, func(object client.Object) []string {
		provider := object.(*v1alpha1.AuthentikApplication).Spec.Provider
		if provider == nil || provider.OAuth2 == nil || provider.OAuth2.Credentials == nil {
			return nil
		}
		return []string{provider.OAuth2.Credentials.SecretRef.Name}
	})
}

// credentialsSecretRequests enqueues the resources in the namespace of the Secret whose credentials refer to it,
// so that a change of the Secret is applied to authentik.
func (r *AuthentikApplicationReconciler) credentialsSecretRequests(ctx context.Context, object client.Object) []reconcile.Request {
	var list v1alpha1.AuthentikApplicationList
	if err := r.List(ctx, &list, client.InNamespace(object.GetNamespace()),
		client.MatchingFields{credentialsSecretIndexField: object.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, app := range list.Items {
		requests = append(requests, reconcile.Request{Namespace: app.Namespace, Name: app.Name})
	}
	return requests
}

// exportCredentials writes the client ID and the client secret of the OAuth2 Provider into a new Secret owned by
// the resource, when the credentials Secret does not exist (docs/spec.md §2.5). From then on the Secret is the
// source of truth. The client ID is written only when the spec does not have clientID.
func (r *AuthentikApplicationReconciler) exportCredentials(ctx context.Context, s *reconcileState, providerPK int32) error {
	spec := s.app.Spec.Provider.OAuth2.Credentials
	provider, err := r.Authentik.GetOAuth2Provider(ctx, providerPK)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		Namespace: s.app.Namespace,
		Name:      spec.SecretRef.Name,
		Type:      corev1.SecretTypeOpaque,
		Data:      map[string][]byte{},
	}
	if spec.ClientID == nil && provider.ClientId != nil {
		secret.Data[*cmp.Or(spec.SecretRef.ClientIDKey, new(reference.DefaultClientIDKey))] = []byte(*provider.ClientId)
	}
	if provider.ClientSecret != nil {
		secret.Data[*cmp.Or(spec.SecretRef.ClientSecretKey, new(reference.DefaultClientSecretKey))] = []byte(*provider.ClientSecret)
	}
	if err := controllerutil.SetControllerReference(s.app, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set the owner of Secret %s: %w", secret.Name, err)
	}
	// Create fails when the Secret appeared since it was read, and the next reconcile uses it as the source of truth.
	if err := r.Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	r.Recorder.Eventf(s.app, secret, corev1.EventTypeNormal, eventReasonCreated, eventActionReconcile,
		"Created Secret %q with the credentials of the OAuth2 Provider", secret.Name)
	return nil
}
