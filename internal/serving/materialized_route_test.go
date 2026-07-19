package serving

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaterializedRouteCanonicalIdentityAndPaths(t *testing.T) {
	exact := "dists/jammy/Release\t4\t" + strings.Repeat("1", 64) + "\n" +
		"pool/main/p/pkg.deb\t7\t" + strings.Repeat("2", 64) + "\n"
	payload := "pool/main/p/pkg.deb\t7\t" + strings.Repeat("2", 64) + "\n"
	identity := MaterializedRouteIdentity{
		Kind: "apt", View: "beta", Source: "beta",
		TargetSHA256: strings.Repeat("a", 64), Claims: []MaterializedRouteClaim{{Kind: MaterializedRouteClaimPrefix, RelativeRoot: ".sow/materialized/beta/apt/pgdg"}},
		ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), Repo: "pgdg", OS: "jammy", Arch: "all",
		Refs: []MaterializedRouteRef{
			{Name: "refs/sow/views/beta/pgdg/jammy/arm64", Commit: strings.Repeat("d", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1},
			{Name: "refs/sow/views/beta/pgdg/jammy/amd64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("e", 40), ManifestSize: 1},
		},
	}
	route, err := NewMaterializedRoute(identity, strings.NewReader(exact), strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if route.Refs[0].Name != "refs/sow/views/beta/pgdg/jammy/amd64" {
		t.Fatalf("refs were not canonicalized: %#v", route.Refs)
	}
	body, err := route.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMaterializedRoute(body)
	if err != nil || decoded.ContentSHA256 != route.ContentSHA256 || decoded.ID != route.ID {
		t.Fatalf("canonical round trip: decoded=%#v err=%v", decoded, err)
	}
	wantPrefix := "serving/materializations/" + strings.Repeat("a", 64) + "/beta/routes/" + route.ID
	receipt, err := MaterializedRouteReceiptStatePath(route)
	if err != nil || receipt != wantPrefix+".json" {
		t.Fatalf("receipt path=%q err=%v", receipt, err)
	}
	exactPath, err := MaterializedRouteExactManifestStatePath(route)
	if err != nil || exactPath != wantPrefix+".exact.tsv" {
		t.Fatalf("exact path=%q err=%v", exactPath, err)
	}
	payloadPath, err := MaterializedRoutePayloadManifestStatePath(route)
	if err != nil || payloadPath != wantPrefix+".payload.tsv" {
		t.Fatalf("payload path=%q err=%v", payloadPath, err)
	}

	// A later materialization of the same physical coordinate replaces the
	// stable ledger path while changing the all-input content identity.
	identity.ConfigSHA256 = strings.Repeat("e", 64)
	later, err := NewMaterializedRoute(identity, strings.NewReader(exact), strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if later.ID != route.ID || later.ContentSHA256 == route.ContentSHA256 {
		t.Fatalf("stable coordinate/content split lost: before=%#v after=%#v", route, later)
	}
}

func TestMaterializedRouteRejectsAnyUnboundMutation(t *testing.T) {
	route := testMaterializedRoute(t)
	cases := map[string]func(*MaterializedRoute){
		"schema":           func(value *MaterializedRoute) { value.Schema = "other" },
		"id":               func(value *MaterializedRoute) { value.ID = strings.Repeat("0", 64) },
		"content":          func(value *MaterializedRoute) { value.ContentSHA256 = strings.Repeat("0", 64) },
		"kind":             func(value *MaterializedRoute) { value.Kind = "asset" },
		"view":             func(value *MaterializedRoute) { value.View = "stable" },
		"source":           func(value *MaterializedRoute) { value.Source = "stable" },
		"target":           func(value *MaterializedRoute) { value.TargetSHA256 = strings.Repeat("0", 64) },
		"claims":           func(value *MaterializedRoute) { value.Claims[0].RelativeRoot = "yum/other" },
		"config":           func(value *MaterializedRoute) { value.ConfigSHA256 = strings.Repeat("0", 64) },
		"config-commit":    func(value *MaterializedRoute) { value.ConfigCommit = strings.Repeat("0", 40) },
		"repo":             func(value *MaterializedRoute) { value.Repo = "other" },
		"os":               func(value *MaterializedRoute) { value.OS = "el9" },
		"arch":             func(value *MaterializedRoute) { value.Arch = "aarch64" },
		"ref-name":         func(value *MaterializedRoute) { value.Refs[0].Name = "refs/sow/views/latest/other/el8/x86_64" },
		"ref-commit":       func(value *MaterializedRoute) { value.Refs[0].Commit = strings.Repeat("9", 40) },
		"ref-manifest":     func(value *MaterializedRoute) { value.Refs[0].ManifestBlob = strings.Repeat("9", 40) },
		"ref-size":         func(value *MaterializedRoute) { value.Refs[0].ManifestSize++ },
		"exact-manifest":   func(value *MaterializedRoute) { value.ExactManifestSHA256 = strings.Repeat("0", 64) },
		"payload-manifest": func(value *MaterializedRoute) { value.PayloadManifestSHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := route
			changed.Refs = append([]MaterializedRouteRef(nil), route.Refs...)
			changed.Claims = append([]MaterializedRouteClaim(nil), route.Claims...)
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("mutated receipt was accepted")
			}
		})
	}
}

func TestMaterializedRouteRejectsUnsupportedSHA256GitObjectIDs(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*MaterializedRouteIdentity)
	}{
		{"config commit", func(identity *MaterializedRouteIdentity) { identity.ConfigCommit = strings.Repeat("a", 64) }},
		{"ref commit", func(identity *MaterializedRouteIdentity) { identity.Refs[0].Commit = strings.Repeat("a", 64) }},
		{"manifest blob", func(identity *MaterializedRouteIdentity) { identity.Refs[0].ManifestBlob = strings.Repeat("a", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := testMaterializedRouteIdentity()
			test.edit(&identity)
			if _, err := NewMaterializedRoute(identity, strings.NewReader("yum/infra/x86_64/Packages/p/pkg.rpm\t1\t"+strings.Repeat("1", 64)+"\n"), strings.NewReader("yum/infra/x86_64/Packages/p/pkg.rpm\t1\t"+strings.Repeat("1", 64)+"\n")); err == nil {
				t.Fatal("64-hex Git object ID was accepted by SHA-1 route schema")
			}
		})
	}
}

func TestDecodeMaterializedRouteRejectsUnknownTrailingAndNonCanonicalJSON(t *testing.T) {
	route := testMaterializedRoute(t)
	body, err := route.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), body[:len(body)-1]...), []byte(",\"unknown\":true}")...)
	if _, err := DecodeMaterializedRoute(unknown); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := DecodeMaterializedRoute(append(body, '\n')); err == nil {
		t.Fatal("non-canonical trailing whitespace was accepted")
	}
	if _, err := DecodeMaterializedRoute(append(append([]byte(nil), body...), []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	indented := &bytes.Buffer{}
	indented.WriteByte(' ')
	indented.Write(body)
	if _, err := DecodeMaterializedRoute(indented.Bytes()); err == nil {
		t.Fatal("non-canonical leading whitespace was accepted")
	}
}

func TestNewMaterializedRouteRejectsMalformedManifestAndDuplicateRefs(t *testing.T) {
	identity := testMaterializedRouteIdentity()
	if _, err := NewMaterializedRoute(identity, strings.NewReader("not-a-manifest\n"), strings.NewReader("")); err == nil {
		t.Fatal("malformed exact manifest was accepted")
	}
	identity.Refs = append(identity.Refs, identity.Refs[0])
	if _, err := NewMaterializedRoute(identity, strings.NewReader(""), strings.NewReader("")); err == nil {
		t.Fatal("duplicate ref was accepted")
	}
}

func testMaterializedRoute(t *testing.T) MaterializedRoute {
	t.Helper()
	entry := "Packages/p/pkg.rpm\t4\t" + strings.Repeat("1", 64) + "\n"
	route, err := NewMaterializedRoute(testMaterializedRouteIdentity(), strings.NewReader(entry), strings.NewReader(entry))
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func testMaterializedRouteIdentity() MaterializedRouteIdentity {
	return MaterializedRouteIdentity{
		Kind: "yum", View: "latest", Source: "latest",
		TargetSHA256: strings.Repeat("a", 64), Claims: []MaterializedRouteClaim{
			{Kind: MaterializedRouteClaimPrefix, RelativeRoot: "yum/infra/x86_64"},
			{Kind: MaterializedRouteClaimGeneration, RelativeRoot: "_sow/v1/g", Leaf: "yum/infra/x86_64"},
		},
		ConfigSHA256: strings.Repeat("b", 64), ConfigCommit: strings.Repeat("e", 40), ServingTargetID: strings.Repeat("9", 64), Repo: "infra", OS: "el8", Arch: "x86_64",
		Refs: []MaterializedRouteRef{{
			Name: "refs/sow/views/latest/infra/el8/x86_64", Commit: strings.Repeat("c", 40), ManifestBlob: strings.Repeat("f", 40), ManifestSize: 1,
		}},
	}
}
