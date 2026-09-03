// Copyright (c) 2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"context"

	"github.com/bborbe/errors"
	"gopkg.in/yaml.v3"
)

// Consent is the three-valued outcome of reading `.maintainer.yaml:
// goUpdate.autoUpdate` for one repo.
//
//   - GrantedConsent — the key is present and explicitly boolean true.
//   - RefusedConsent — the key is present and explicitly boolean false.
//   - UndecidedConsent — the file is absent, the goUpdate section is absent,
//     the autoUpdate key is absent, or the key holds any non-boolean value.
//
// The vuln watcher's gate treats both RefusedConsent and UndecidedConsent as
// "auto_update_disabled" — only GrantedConsent passes.
type Consent string

const (
	GrantedConsent   Consent = "granted"
	RefusedConsent   Consent = "refused"
	UndecidedConsent Consent = "undecided"
)

// maintainerDoc is the minimal shape ParseConsent needs to reach the
// goUpdate.autoUpdate node as a raw yaml.Node, so it can tell "absent" from
// "present and false" apart.
type maintainerDoc struct {
	GoUpdate struct {
		AutoUpdate yaml.Node `yaml:"autoUpdate"`
	} `yaml:"goUpdate"`
}

// ParseConsent reads raw `.maintainer.yaml` bytes and returns the consent
// verdict. Returns (Consent(""), non-nil error) when content is not valid YAML
// at all — the caller MUST treat a non-nil error as a drop-before-evaluation,
// never read the zero-value Consent as a verdict.
func ParseConsent(ctx context.Context, content []byte) (Consent, error) {
	if len(content) == 0 {
		return UndecidedConsent, nil
	}

	var doc maintainerDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return Consent(""), errors.Wrapf(ctx, err, "parse .maintainer.yaml")
	}

	node := doc.GoUpdate.AutoUpdate
	if node.Kind == 0 {
		return UndecidedConsent, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return UndecidedConsent, nil
	}
	switch node.Value {
	case "true", "True", "TRUE":
		return GrantedConsent, nil
	case "false", "False", "FALSE":
		return RefusedConsent, nil
	default:
		return UndecidedConsent, nil
	}
}
