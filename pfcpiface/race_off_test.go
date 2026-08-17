// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package pfcpiface

// raceEnabled reports whether this binary was built with the race detector.
//
// It exists for the allocation-count assertions in this package. testing.AllocsPerRun
// counts every allocation the process makes, including the ones the race detector makes
// on its own account, so an assertion that a second delivery destination costs no extra
// allocation is measuring the instrumentation rather than the code once -race is on.
//
// This is not hypothetical: `make test` runs with -race, and
// TestSecondDestinationCostsOnlyItsDelivery has been failing there — 14 allocations
// against 15 — since it was written, identically at every commit. The assertion is
// sound without the detector and cannot be made sound with it.
const raceEnabled = false
