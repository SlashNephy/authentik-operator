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

package reference

import (
	"fmt"
	"strings"

	"github.com/SlashNephy/authentik-operator/api/v1alpha1"
)

// Failure is a reference that could not be resolved.
type Failure struct {
	// Path is the path of the reference in the spec, such as access.rules[1].group.
	Path string
	// Target describes what was looked up, such as `Group name "admins"`.
	Target string
	// Matches is the number of objects found. 0 means not found; more than 1 means ambiguous.
	Matches int
}

// Ambiguous reports whether the reference matched several objects.
func (f Failure) Ambiguous() bool {
	return f.Matches > 1
}

func (f Failure) String() string {
	if f.Ambiguous() {
		return fmt.Sprintf("%s: %s matches %d objects", f.Path, f.Target, f.Matches)
	}
	return fmt.Sprintf("%s: %s not found", f.Path, f.Target)
}

// Error is returned when one or more references cannot be resolved (docs/spec.md §3.6).
// It lists every failed reference, not only the first one.
type Error struct {
	Failures []Failure
}

func (e *Error) Error() string {
	messages := make([]string, 0, len(e.Failures))
	for _, failure := range e.Failures {
		messages = append(messages, failure.String())
	}
	return "unresolved references: " + strings.Join(messages, "; ")
}

// Reason returns the reason of the Ready condition.
// ReferenceNotFound takes precedence when some references are missing and others are ambiguous.
func (e *Error) Reason() string {
	for _, failure := range e.Failures {
		if !failure.Ambiguous() {
			return v1alpha1.ReasonReferenceNotFound
		}
	}
	return v1alpha1.ReasonAmbiguousReference
}

// collector accumulates failures so that every reference is checked before reporting.
type collector struct {
	failures []Failure
}

func (c *collector) add(path, target string, matches int) {
	c.failures = append(c.failures, Failure{Path: path, Target: target, Matches: matches})
}

// err returns an *Error when any failure was recorded.
func (c *collector) err() error {
	if len(c.failures) == 0 {
		return nil
	}
	return &Error{Failures: c.failures}
}
