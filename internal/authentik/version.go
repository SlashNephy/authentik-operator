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
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
)

// clientModulePath is the module path of client-go, whose version determines the supported authentik minor version.
const clientModulePath = "goauthentik.io/api/v3"

// SupportedVersion returns the authentik minor version (such as 2026.8) that matches the client-go module linked
// into the binary (docs/spec.md §6).
func SupportedVersion() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("build information is not available")
	}
	for _, dep := range info.Deps {
		if dep.Path != clientModulePath {
			continue
		}
		if dep.Replace != nil {
			dep = dep.Replace
		}
		return minorFromClientVersion(dep.Version)
	}
	return "", fmt.Errorf("module %s is not in the build information", clientModulePath)
}

// minorFromClientVersion converts a client-go tag such as v3.2026080.2 into the authentik minor version 2026.8.
// The middle component encodes the authentik version as the year, a two-digit minor version, and a trailing digit.
func minorFromClientVersion(version string) (string, error) {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) < 2 || len(parts[1]) != 7 {
		return "", fmt.Errorf("unexpected client-go version %q", version)
	}
	year, err := strconv.Atoi(parts[1][:4])
	if err != nil {
		return "", fmt.Errorf("unexpected client-go version %q: %w", version, err)
	}
	minor, err := strconv.Atoi(parts[1][4:6])
	if err != nil {
		return "", fmt.Errorf("unexpected client-go version %q: %w", version, err)
	}
	return fmt.Sprintf("%d.%d", year, minor), nil
}

// minorFromServerVersion converts an authentik version such as 2026.8.2 or 2026.8.0-rc1 into 2026.8.
func minorFromServerVersion(version string) (string, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected authentik version %q", version)
	}
	year, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("unexpected authentik version %q: %w", version, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("unexpected authentik version %q: %w", version, err)
	}
	return fmt.Sprintf("%d.%d", year, minor), nil
}

// CheckVersion compares the authentik server minor version with the supported one.
// A mismatch is reported as a warning log and the authentik_operator_authentik_version_mismatch metric;
// it does not stop the operator. It returns whether the minor versions match.
func CheckVersion(ctx context.Context, client VersionClient, supported string, log logr.Logger) (bool, error) {
	version, err := client.GetVersion(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to read the authentik version: %w", err)
	}
	server, err := minorFromServerVersion(version.VersionCurrent)
	if err != nil {
		return false, err
	}

	versionMismatch.Reset()
	if server != supported {
		versionMismatch.WithLabelValues(version.VersionCurrent, supported).Set(1)
		log.Info("WARNING: the authentik minor version differs from the version this operator supports; upgrade the operator together with authentik",
			"serverVersion", version.VersionCurrent, "supportedVersion", supported)
		return false, nil
	}
	versionMismatch.WithLabelValues(version.VersionCurrent, supported).Set(0)
	log.Info("authentik version is supported", "serverVersion", version.VersionCurrent, "supportedVersion", supported)
	return true, nil
}
