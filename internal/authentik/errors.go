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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// ErrNotFound is matched by errors.Is when authentik answers 404 for the requested object.
var ErrNotFound = errors.New("authentik object not found")

// maxErrorBodyLength limits how much of a response body is kept in an APIError.
const maxErrorBodyLength = 4096

// Redacted replaces confidential values that would otherwise be shown to the user (docs/spec.md §5).
const Redacted = "(redacted)"

// ConfidentialFields are API fields whose values are never shown outside the operator (docs/spec.md §5).
// Error bodies are echoed into the conditions and the Events of a resource, where they are readable by anyone
// who can read the resource, so the values of these fields are removed before they are kept.
var ConfidentialFields = []string{"client_secret", "password", "token"}

// APIError is returned when authentik answers with a non-2xx status code.
type APIError struct {
	// Operation is the name of the client method that failed, such as GetApplication.
	Operation string
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Body is the response body, truncated to a bounded length. For 400 responses it describes the invalid fields.
	Body string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("authentik API %s returned %d: %s", e.Operation, e.StatusCode, e.Body)
}

// Is reports whether the error is ErrNotFound, so that callers can use errors.Is(err, ErrNotFound).
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// wrapError converts the result of a client-go call into an error that callers can inspect.
// A non-2xx response becomes an *APIError; a transport error is wrapped with the operation name.
func wrapError(operation string, resp *http.Response, err error) error {
	if resp != nil && (resp.StatusCode < 200 || resp.StatusCode > 299) {
		return &APIError{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Body:       errorBody(resp, err),
		}
	}
	if err != nil {
		return fmt.Errorf("authentik API %s failed: %w", operation, err)
	}
	return nil
}

// errorBody returns the response body of a failed call. client-go has already consumed the body
// and keeps a copy in GenericOpenAPIError, so that copy is preferred.
func errorBody(resp *http.Response, err error) string {
	var body []byte
	var openAPIErr interface{ Body() []byte }
	if errors.As(err, &openAPIErr) {
		body = openAPIErr.Body()
	} else if resp.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLength))
	}
	redacted := redactBody(body)
	if len(redacted) > maxErrorBodyLength {
		redacted = redacted[:maxErrorBodyLength]
	}
	return redacted
}

// redactBody removes the values of the confidential fields from a JSON body. A body that is not JSON is kept
// as it is, because it carries no request payload.
func redactBody(body []byte) string {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return string(body)
	}
	redactValue(value)
	out, err := json.Marshal(value)
	if err != nil {
		return string(body)
	}
	return string(out)
}

// redactValue replaces the values of the confidential fields in place.
func redactValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if slices.Contains(ConfidentialFields, key) {
				typed[key] = Redacted
				continue
			}
			redactValue(child)
		}
	case []any:
		for _, child := range typed {
			redactValue(child)
		}
	}
}
