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
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const metricsNamespace = "authentik_operator"

var (
	// requestsTotal counts authentik API requests by client operation and HTTP status code.
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "authentik_api",
		Name:      "requests_total",
		Help:      "Number of authentik API requests by operation and HTTP status code (\"error\" when no response was received).",
	}, []string{"operation", "code"})

	// requestDuration observes the latency of authentik API requests by client operation.
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: "authentik_api",
		Name:      "request_duration_seconds",
		Help:      "Latency of authentik API requests by operation.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"operation"})

	// versionMismatch is 1 when the authentik server minor version differs from the one the operator supports.
	versionMismatch = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "authentik_version_mismatch",
		Help:      "1 when the authentik server minor version differs from the minor version supported by the operator, 0 otherwise.",
	}, []string{"server_version", "supported_version"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(requestsTotal, requestDuration, versionMismatch)
}

// observeRequest records the outcome and latency of one API request.
func observeRequest(operation string, start time.Time, resp *http.Response) {
	code := "error"
	if resp != nil {
		code = strconv.Itoa(resp.StatusCode)
	}
	requestsTotal.WithLabelValues(operation, code).Inc()
	requestDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())
}
