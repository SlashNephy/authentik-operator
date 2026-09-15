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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	// cfg and k8sClient talk to the envtest API server that has the generated CRDs installed.
	cfg       *rest.Config
	k8sClient client.Client
	scheme    = runtime.NewScheme()
	// indexedClient reads and writes like k8sClient, but lists from a cache that has the slug index, as the
	// client of the manager does.
	indexedClient client.Client
)

// cacheListClient lists from a cache and performs every other operation with the embedded client.
type cacheListClient struct {
	client.Client
	cache cache.Cache
}

func (c *cacheListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.cache.List(ctx, list, opts...)
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start envtest (run the tests with `make test`, which sets KUBEBUILDER_ASSETS): %v\n", err)
		return 1
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop envtest: %v\n", err)
		}
	}()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to register the Kubernetes types: %v\n", err)
		return 1
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to register the API types: %v\n", err)
		return 1
	}
	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create a Kubernetes client: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informers, err := cache.New(cfg, cache.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create a cache: %v\n", err)
		return 1
	}
	if err := IndexSlug(ctx, informers); err != nil {
		fmt.Fprintf(os.Stderr, "failed to index the slug: %v\n", err)
		return 1
	}
	if err := IndexCredentialsSecret(ctx, informers); err != nil {
		fmt.Fprintf(os.Stderr, "failed to index the credentials Secret: %v\n", err)
		return 1
	}
	go func() {
		if err := informers.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start the cache: %v\n", err)
		}
	}()
	if _, err := informers.GetInformer(ctx, &v1alpha1.AuthentikApplication{}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the informer: %v\n", err)
		return 1
	}
	indexedClient = &cacheListClient{Client: k8sClient, cache: informers}

	return m.Run()
}
