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

package authentik

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// requestTimeout bounds a single authentik API request.
const requestTimeout = 30 * time.Second

// Config holds the connection settings of the authentik API (docs/spec.md §4).
type Config struct {
	// URL is the root URL of authentik (AUTHENTIK_URL).
	URL string
	// Token is the API token (AUTHENTIK_TOKEN).
	Token string
	// CAFile is a PEM file with additional CA certificates to trust (--authentik-ca-file).
	CAFile string
	// Insecure disables TLS certificate verification (--authentik-insecure).
	Insecure bool
}

// Validate reports missing or conflicting settings.
func (c *Config) Validate() error {
	var errs []error
	if c.URL == "" {
		errs = append(errs, errors.New("the authentik URL is required (AUTHENTIK_URL)"))
	}
	if c.Token == "" {
		errs = append(errs, errors.New("the authentik API token is required (AUTHENTIK_TOKEN)"))
	}
	if c.CAFile != "" && c.Insecure {
		errs = append(errs, errors.New("--authentik-ca-file and --authentik-insecure cannot be used together"))
	}
	return errors.Join(errs...)
}

// NewHTTPClient returns an HTTP client with the TLS settings of the config.
func NewHTTPClient(cfg *Config) (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not an *http.Transport")
	}
	transport = transport.Clone()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read the authentik CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no PEM certificates found in the authentik CA file %q", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.Insecure {
		// Explicitly requested with --authentik-insecure.
		tlsConfig.InsecureSkipVerify = true
	}
	transport.TLSClientConfig = tlsConfig

	return &http.Client{Transport: transport, Timeout: requestTimeout}, nil
}

// New validates the config and returns a Client for the authentik API.
func New(cfg *Config) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	httpClient, err := NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	apiClient, err := NewAPIClient(cfg.URL, cfg.Token, httpClient)
	if err != nil {
		return nil, err
	}
	return &client{api: apiClient}, nil
}
