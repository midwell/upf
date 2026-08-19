// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// strictLiBlock re-decodes the `li` object on its own, refusing a key this element does not
// model.
//
// **A misspelled LI key is silently dropped by encoding/json, and the defaults it lands on are the
// dangerous ones.** A typo'd `trigger_keepalive` leaves the fail-safe *off*, so this CC-POI keeps
// duplicating content after the triggering function responsible for it is gone — past the point
// where the warrant itself is revoked. A typo'd `admf_url` leaves the fault channel a no-op, so
// every condition this element is required to report goes nowhere, including the report that would
// have said the configuration was wrong. In both cases the operator wrote the setting, the element
// ignored it, and nothing anywhere says so.
//
// `validateLiConfig` already refuses an *absent* mandatory key. It cannot see a misspelled one:
// from its side the two are identical, and the settings above are the ones where the difference
// matters most, because neither is mandatory and both fail unsafely.
//
// **Scoped to the `li` object, deliberately.** Passing DisallowUnknownFields over the whole
// configuration would refuse upstream keys this fork does not model, which is a different and much
// larger change: the fork tracks an upstream that adds fields, and a deployment carrying one would
// stop starting. The property to hold is narrow — a mistyped LI key must not reach a default — and
// so is the check.
func strictLiBlock(jsonData []byte) error {
	// Only the top level, so that no key outside `li` is ever presented to the strict decode.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &top); err != nil {
		// A document this cannot read is the real decode's to report, with its own message.
		return nil
	}

	raw, ok := top["li"]
	if !ok {
		// No `li` object: interception is off, and there is nothing to be strict about.
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var li LiConfig
	if err := dec.Decode(&li); err != nil {
		return fmt.Errorf("li: %w — a key this element does not recognise is a setting that never "+
			"reaches it, and the defaults it leaves in place are the unsafe ones: an unread "+
			"trigger_keepalive leaves this CC-POI duplicating content no triggering function can "+
			"withdraw, and an unread admf_url leaves it with no channel to report that on", err)
	}

	return nil
}
