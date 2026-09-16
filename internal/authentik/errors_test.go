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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openAPIError carries the response body the way the generated client does.
type openAPIError struct {
	body []byte
}

func (e *openAPIError) Error() string { return "openapi" }
func (e *openAPIError) Body() []byte  { return e.body }

func TestErrorBodyRedactsConfidentialValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		want   string
		isJSON bool
	}{
		{
			name:   "the echoed client secret is removed",
			body:   `{"client_id":"chat","client_secret":"super-secret"}`,
			want:   `{"client_id":"chat","client_secret":"(redacted)"}`,
			isJSON: true,
		},
		{
			name:   "confidential values nested in a list are removed",
			body:   `{"providers":[{"name":"chat","token":"abcd"}]}`,
			want:   `{"providers":[{"name":"chat","token":"(redacted)"}]}`,
			isJSON: true,
		},
		{
			name:   "the validation errors of a field are kept",
			body:   `{"client_secret":["This field may not be blank."]}`,
			want:   `{"client_secret":["This field may not be blank."]}`,
			isJSON: true,
		},
		{
			name: "a body that is not JSON is kept",
			body: "<html>502 Bad Gateway</html>",
			want: "<html>502 Bad Gateway</html>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp := &http.Response{StatusCode: http.StatusBadRequest}
			err := wrapError("CreateOAuth2Provider", resp, &openAPIError{body: []byte(tt.body)})
			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			if tt.isJSON {
				assert.JSONEq(t, tt.want, apiErr.Body)
			} else {
				assert.Equal(t, tt.want, apiErr.Body)
			}
			assert.NotContains(t, err.Error(), "super-secret")
		})
	}
}

func TestErrorBodyIsTruncated(t *testing.T) {
	t.Parallel()

	resp := &http.Response{StatusCode: http.StatusBadRequest}
	err := wrapError("GetApplication", resp, &openAPIError{body: []byte(strings.Repeat("x", maxErrorBodyLength*2))})
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Len(t, apiErr.Body, maxErrorBodyLength)
}
