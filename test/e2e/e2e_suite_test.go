//go:build e2e

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

// Package e2e tests the operator installed with its chart against authentik on kind (docs/spec.md §6).
// Run it with make test-e2e, which starts authentik with hack/authentik/up.sh and installs the operator with
// hack/e2e/deploy.sh.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
	"github.com/SlashNephy/authentik-operator/internal/authentik"
)

var (
	// k8s talks to the kind cluster in the current kubeconfig context.
	k8s client.Client
	// ak talks to authentik through a port-forward with the bootstrap token.
	ak authentik.Client
	// authentikURL and authentikToken are used for API calls that the client does not cover.
	authentikURL   string
	authentikToken string
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func run(m *testing.M) int {
	namespace := getenv("AUTHENTIK_NAMESPACE", "authentik")
	release := getenv("AUTHENTIK_RELEASE", "authentik")
	port := getenv("AUTHENTIK_LOCAL_PORT", "9100")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fail("register the Kubernetes types", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return fail("register the API types", err)
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fail("load the kubeconfig", err)
	}
	if k8s, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
		return fail("create a Kubernetes client", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bootstrap := &corev1.Secret{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "authentik-bootstrap"}, bootstrap); err != nil {
		return fail("read the authentik bootstrap Secret", err)
	}
	authentikToken = string(bootstrap.Data["AUTHENTIK_BOOTSTRAP_TOKEN"])

	service := "svc/" + release + "-server"
	portForward := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward", service, port+":80")
	if err := portForward.Start(); err != nil {
		return fail("start the port-forward to authentik", err)
	}
	defer func() { _ = portForward.Process.Kill() }()

	authentikURL = "http://localhost:" + port
	if err := waitForAuthentik(ctx); err != nil {
		return fail("wait for authentik", err)
	}
	if ak, err = authentik.New(&authentik.Config{URL: authentikURL, Token: authentikToken}); err != nil {
		return fail("create the authentik client", err)
	}

	return m.Run()
}

func waitForAuthentik(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, authentikURL+"/-/health/ready/", nil)
		if err != nil {
			return err
		}
		if response, err := http.DefaultClient.Do(request); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("authentik at %s is not ready", authentikURL)
}

func fail(action string, err error) int {
	fmt.Fprintf(os.Stderr, "failed to %s: %v\n", action, err)
	return 1
}
