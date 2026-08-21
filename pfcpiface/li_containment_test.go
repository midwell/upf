// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestStrictLiBlockDoesNotFailTheConfigurationLoad is a source-level assertion, and it exists
// because this element already learned the lesson once and then repeated it one layer up.
//
// `startLIShipper` carries the record of it: *"The configuration is checked here, and not in
// validateConf, because a refusal there took the user plane down and named the offending LI field
// in the general operator log."* The strict `li` decode then did exactly that again from
// `LoadConfigFile`, whose only caller answers an error with `Fatalln` — so one mistyped LI key
// crash-looped the element carrying every subscriber's traffic, and echoed the offending key into
// the operator log four lines above the comment forbidding it.
//
// This is the worst of the three network functions to get wrong. The AMF and SMF stop signalling;
// this one stops forwarding. And a user plane that will not start is the loudest possible
// disclosure that the element is LI-provisioned — visible to every operator, every peer and every
// monitoring system, where a log line is visible only to whoever reads logs.
//
// The rule: whatever statement carries the `strictLiBlock` call must not return from it. The
// verdict is recorded on the LI object and acted on by the LI subsystem, where the ADMF can be
// told. See LiConfig.blockErr and startLIShipper.
func TestStrictLiBlockDoesNotFailTheConfigurationLoad(t *testing.T) {
	const file = "config.go"

	fset := token.NewFileSet()

	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	// The statement that carries the call, whatever shape it takes.
	var carrier ast.Node

	ast.Inspect(parsed, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.AssignStmt, *ast.ExprStmt, *ast.ReturnStmt:
		default:
			return true
		}

		ast.Inspect(n, func(inner ast.Node) bool {
			call, isCall := inner.(*ast.CallExpr)
			if !isCall {
				return true
			}

			if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "strictLiBlock" {
				if carrier == nil {
					carrier = n
				}
			}

			return true
		})

		return true
	})

	if carrier == nil {
		t.Fatalf("no call to strictLiBlock in %s; if the strict LI decode moved, move this guard "+
			"with it rather than deleting it — the property it holds is that a refused LI block "+
			"never stops the user plane", file)
	}

	if _, isReturn := carrier.(*ast.ReturnStmt); isReturn {
		t.Fatalf("%s: strictLiBlock's verdict is returned directly from the configuration load, "+
			"which reaches cmd/pfcpiface's Fatalln and crash-loops the user plane over an "+
			"optional subsystem", file)
	}

	var (
		returns  bool
		recorded bool
	)

	ast.Inspect(carrier, func(n ast.Node) bool {
		// A nested function literal has its own return, which is its own business.
		if _, isFunc := n.(*ast.FuncLit); isFunc {
			return false
		}

		if _, isReturn := n.(*ast.ReturnStmt); isReturn {
			returns = true
		}

		if sel, isSel := n.(*ast.SelectorExpr); isSel && sel.Sel != nil && sel.Sel.Name == "blockErr" {
			recorded = true
		}

		return true
	})

	if returns {
		t.Errorf("%s: the statement carrying strictLiBlock returns. A refused `li` object must "+
			"stop interception and nothing else — returning here fails LoadConfigFile, which "+
			"cmd/pfcpiface answers with Fatalln, taking every subscriber's traffic down over a "+
			"typo in an optional subsystem.", file)
	}

	if !recorded {
		t.Errorf("%s: strictLiBlock's verdict is not recorded on the LI object's blockErr, so "+
			"nothing downstream can act on it. Record it and let startLIShipper refuse "+
			"interception on it, where the ADMF can be told.", file)
	}
}

// TestTheStrictLiDecodeIsStillStrict guards the other direction. The containment fix is a narrow
// one — who acts on the refusal — and it must not be read, or implemented, as backing out the
// strictness that produced it.
func TestTheStrictLiDecodeIsStillStrict(t *testing.T) {
	const body = `{
		"mode": "dpdk",
		"li": {
			"x3_sockaddr": "/pod-share/x3",
			"ne_id": "upf-1",
			"trigger_keepalve": "5m"
		}
	}`

	if err := strictLiBlock([]byte(body)); err == nil {
		t.Error("a misspelled LI key was accepted by the strict decode; the containment fix is " +
			"about who acts on the refusal, not about whether there is one")
	}
}
