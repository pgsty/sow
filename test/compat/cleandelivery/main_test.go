package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParsePathListRejectsUnsafeDuplicateAndUnsortedPaths(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"absolute":  "/etc/passwd\n",
		"traversal": "../escape\n",
		"duplicate": "a\na\n",
		"unsorted":  "b\na\n",
		"cache":     "internal/.cache/object\n",
		"secret":    "internal/.env.production\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parsePathList(name, []byte(input)); err == nil {
				t.Fatalf("parsePathList accepted %q", input)
			}
		})
	}
}

func TestAuditSourceRejectsExtraRegularSymlinkAndNamedCache(t *testing.T) {
	t.Parallel()
	for name, create := range map[string]func(t *testing.T, root string){
		"extra regular": func(t *testing.T, root string) {
			writeFixture(t, root, "src/extra.go", "package src\n", 0o644)
		},
		"symlink": func(t *testing.T, root string) {
			if runtime.GOOS == "windows" {
				t.Skip("symlink fixture requires Unix permissions")
			}
			if err := os.Symlink("allowed.go", filepath.Join(root, "src", "alias.go")); err != nil {
				t.Fatal(err)
			}
		},
		"cache directory": func(t *testing.T, root string) {
			writeFixture(t, root, "src/.cache/object", "cached", 0o644)
		},
		"other node modules": func(t *testing.T, root string) {
			writeFixture(t, root, "src/node_modules/package/index.js", "cached", 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFixture(t, root, "src/allowed.go", "package src\n", 0o644)
			create(t, root)
			if err := auditSource(root, []string{"src"}, []string{"src/allowed.go"}); err == nil {
				t.Fatal("auditSource accepted forbidden path")
			}
		})
	}
}

func TestAuditSourceIgnoresOnlyManagedEdgeNodeModules(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "edge/worker.mjs", "export default {}\n", 0o644)
	writeFixture(t, root, "edge/node_modules/dependency/index.js", "generated\n", 0o644)
	if err := auditSource(root, []string{"edge"}, []string{"edge/worker.mjs"}); err != nil {
		t.Fatalf("managed edge/node_modules was not ignored: %v", err)
	}
	writeFixture(t, root, "edge/.cache/object", "generated\n", 0o644)
	if err := auditSource(root, []string{"edge"}, []string{"edge/worker.mjs"}); err == nil {
		t.Fatal("auditSource ignored an unapproved edge cache")
	}
}

func TestAuditSourceRejectsUnsafeRepositoryManagedAndAllowlistedComponents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink component fixtures require Unix semantics")
	}
	t.Run("repository symlink", func(t *testing.T) {
		actual := t.TempDir()
		writeFixture(t, actual, "src/allowed.go", "package src\n", 0o644)
		alias := filepath.Join(t.TempDir(), "repo")
		if err := os.Symlink(actual, alias); err != nil {
			t.Fatal(err)
		}
		if err := auditSource(alias, []string{"src"}, []string{"src/allowed.go"}); err == nil || !strings.Contains(err.Error(), "root is a symlink") {
			t.Fatalf("repository symlink error = %v", err)
		}
	})
	t.Run("repository non-directory", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "repo")
		if err := os.WriteFile(root, []byte("not a directory"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := auditSource(root, []string{"src"}, []string{"src/allowed.go"}); err == nil || !strings.Contains(err.Error(), "root is not a directory") {
			t.Fatalf("repository file error = %v", err)
		}
	})
	for _, fixture := range []struct {
		name   string
		create func(t *testing.T, root string)
		want   string
	}{
		{
			name: "managed root symlink",
			create: func(t *testing.T, root string) {
				outside := t.TempDir()
				writeFixture(t, outside, "allowed.go", "package src\n", 0o644)
				if err := os.Symlink(outside, filepath.Join(root, "src")); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink component",
		},
		{
			name: "managed root non-directory",
			create: func(t *testing.T, root string) {
				writeFixture(t, root, "src", "package src\n", 0o644)
			},
			want: "not a directory",
		},
		{
			name: "bmad parent symlink",
			create: func(t *testing.T, root string) {
				writeFixture(t, root, "src/allowed.go", "package src\n", 0o644)
				outside := t.TempDir()
				writeFixture(t, outside, "planning/spec.md", "# escaped\n", 0o644)
				if err := os.Symlink(outside, filepath.Join(root, "_bmad-output")); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink component",
		},
		{
			name: "bmad nested parent symlink",
			create: func(t *testing.T, root string) {
				writeFixture(t, root, "src/allowed.go", "package src\n", 0o644)
				if err := os.Mkdir(filepath.Join(root, "_bmad-output"), 0o755); err != nil {
					t.Fatal(err)
				}
				outside := t.TempDir()
				writeFixture(t, outside, "spec.md", "# escaped\n", 0o644)
				if err := os.Symlink(outside, filepath.Join(root, "_bmad-output", "planning")); err != nil {
					t.Fatal(err)
				}
			},
			want: "symlink component",
		},
		{
			name: "bmad parent non-directory",
			create: func(t *testing.T, root string) {
				writeFixture(t, root, "src/allowed.go", "package src\n", 0o644)
				writeFixture(t, root, "_bmad-output", "not a directory\n", 0o644)
			},
			want: "not a directory",
		},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			root := t.TempDir()
			fixture.create(t, root)
			allowed := []string{"src/allowed.go"}
			if strings.HasPrefix(fixture.name, "bmad") {
				allowed = append(allowed, "_bmad-output/planning/spec.md")
			}
			err := auditSource(root, []string{"src"}, allowed)
			if err == nil || !strings.Contains(err.Error(), fixture.want) {
				t.Fatalf("auditSource error = %v; want %q", err, fixture.want)
			}
		})
	}
}

func TestAuditAllowedContentRejectsHighConfidenceSecrets(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		"private key":    "-----BEGIN " + "PRIVATE KEY-----\nmaterial\n",
		"indented key":   "  -----BEGIN " + "PGP PRIVATE KEY BLOCK-----\nmaterial\n",
		"aws long-lived": "access_key_id=AKIA" + "ABCDEFGHIJKLMNOP\n",
		"aws temporary":  "access_key_id=ASIA" + "ABCDEFGHIJKLMNOP\n",
		"tencent":        "secret_id=AKID" + strings.Repeat("a", 32) + "\n",
		"github":         "token=ghp_" + strings.Repeat("a", 36) + "\n",
		"github pat":     "token=github_pat_" + strings.Repeat("a", 24) + "\n",
		"slack":          "token=xoxb-" + strings.Repeat("a", 24) + "\n",
		"stripe":         "token=sk_live_" + strings.Repeat("a", 24) + "\n",
	}
	for name, contents := range secrets {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFixture(t, root, "allowed.txt", contents, 0o644)
			if err := auditAllowedContent(root, []string{"allowed.txt"}); err == nil || !strings.Contains(err.Error(), "high-confidence") {
				t.Fatalf("secret scan result = %v", err)
			}
		})
	}
}

func TestAuditAllowedContentRejectsFieldSensitiveProviderSecrets(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		"aws":          "AWS_SECRET_ACCESS_KEY=" + strings.Repeat("a", 40) + "\n",
		"cloudflare":   "CLOUDFLARE_API_TOKEN=" + strings.Repeat("c", 40) + "\n",
		"r2 json":      `{"secret_access_key":"` + strings.Repeat("r", 40) + `"}` + "\n",
		"cos":          "SOW_COS_SECRET_KEY=" + strings.Repeat("t", 32) + "\n",
		"edge bearer":  "SOW_ORIGIN_BEARER=" + strings.Repeat("b", 32) + "\n",
		"basic secret": `{"basic_password":"` + strings.Repeat("p", 32) + `"}` + "\n",
		"pro token a":  "SOW_REAL_EDGE_PRO_TOKEN_A=" + strings.Repeat("e", 32) + "\n",
		"pro token b":  "SOW_REAL_EDGE_PRO_TOKEN_B=" + strings.Repeat("f", 32) + "\n",
	}
	for name, contents := range secrets {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFixture(t, root, "allowed.txt", contents, 0o644)
			if err := auditAllowedContent(root, []string{"allowed.txt"}); err == nil || !strings.Contains(err.Error(), "provider secret assignment") {
				t.Fatalf("provider secret scan result = %v", err)
			}
		})
	}
}

func TestAuditAllowedContentAcceptsDocumentationPatterns(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	contents := strings.Join([]string{
		"Examples: AKIA[0-9A-Z]{16} and -----BEGIN PRIVATE KEY----- inside prose.",
		"AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE",
		"TENCENT_SECRET_ID=AKID" + "EXAMPLE" + strings.Repeat("0", 25),
		"SOW_COS_SECRET_KEY=cos-secret-key-for-contract-tests-only",
		"CLOUDFLARE_API_TOKEN=replace-with-cloudflare-token-value",
		`{"secret_access_key":"fixture-secret-access-key-value"}`,
		`{"basic_password":"cf-private-password"}`,
		"SOW_REAL_EDGE_PRO_TOKEN_A=contract-test-edge-token-value",
	}, "\n") + "\n"
	writeFixture(t, root, "allowed.txt", contents, 0o644)
	if err := auditAllowedContent(root, []string{"allowed.txt"}); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryPolicyClosure(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := auditSource(root, productRoots, p.product); err != nil {
		t.Fatalf("product allowlist: %v", err)
	}
	if err := auditSource(root, deliveryRoots, p.delivery); err != nil {
		t.Fatalf("delivery allowlist: %v", err)
	}
	if err := auditAllowedContent(root, p.delivery); err != nil {
		t.Fatalf("delivery content: %v", err)
	}
	if err := checkMarkdownLinks(root, p.delivery); err != nil {
		t.Fatalf("Markdown closure: %v", err)
	}
}

func TestDeterministicArchiveHasExactBytesAndCanonicalMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "docs/readme.md", "hello\n", 0o600)
	writeFixture(t, root, "test/check.sh", "#!/bin/sh\n", 0o700)
	allowed := []string{"docs/readme.md", "test/check.sh"}
	virtual := map[string][]byte{productManifest: []byte("manifest\n")}
	first := filepath.Join(t.TempDir(), "first.tgz")
	second := filepath.Join(t.TempDir(), "second.tgz")
	if err := writeDeterministicArchive(first, root, allowed, virtual); err != nil {
		t.Fatal(err)
	}
	if err := writeDeterministicArchive(second, root, allowed, virtual); err != nil {
		t.Fatal(err)
	}
	if _, err := compareFilesExact(first, second); err != nil {
		t.Fatal(err)
	}
	extract := t.TempDir()
	if err := extractAndValidate(first, extract, allowed, virtual); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(extract, "test/check.sh")); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("script mode = %v, %v", info, err)
	}
}

func TestMarkdownLinkClosureRejectsMissingAndEscapingTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	allowed := []string{"docs/a.md", "docs/b.md"}
	writeFixture(t, root, "docs/a.md", "[present](b.md#anchor)\n", 0o644)
	writeFixture(t, root, "docs/b.md", "# Anchor\n", 0o644)
	if err := checkMarkdownLinks(root, allowed); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"missing.md", "../../outside.md"} {
		if err := os.WriteFile(filepath.Join(root, "docs/a.md"), []byte("[bad]("+target+")\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkMarkdownLinks(root, allowed); err == nil {
			t.Fatalf("checkMarkdownLinks accepted %s", target)
		}
	}
}

func TestAuditExtractedRejectsPostCommandMutation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	allowed := []string{"a.txt"}
	writeFixture(t, root, "a.txt", "a", 0o644)
	virtual := map[string][]byte{productManifest: []byte("manifest")}
	writeFixture(t, root, productManifest, "manifest", 0o644)
	if err := auditExtracted(root, allowed, virtual); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "unexpected.txt", "bad", 0o644)
	if err := auditExtracted(root, allowed, virtual); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("unexpected mutation error = %v", err)
	}
}

func TestManifestBytesAreStable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, root, "a", "one", 0o644)
	writeFixture(t, root, "b", "two", 0o644)
	first, err := manifestBytes(root, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manifestBytes(root, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(bytes.Split(bytes.TrimSpace(first), []byte("\n"))) != 2 {
		t.Fatalf("unstable manifest:\n%s", first)
	}
}

func TestIsolatedGoEnvironmentPinsVerificationAndAllowsExplicitMirrors(t *testing.T) {
	t.Setenv("SOW_CLEAN_GOPROXY", "https://goproxy.example,direct")
	t.Setenv("SOW_CLEAN_GOSUMDB", "sum.golang.google.cn")
	env, err := isolatedGoEnvironment(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, wanted := range []string{
		"\nGOPROXY=https://goproxy.example,direct\n",
		"\nGOSUMDB=sum.golang.google.cn\n",
		"\nGOPRIVATE=\n",
		"\nGONOPROXY=\n",
		"\nGONOSUMDB=\n",
	} {
		if !strings.Contains(joined, wanted) {
			t.Fatalf("isolated environment omitted %q: %v", wanted, env)
		}
	}
	t.Setenv("SOW_CLEAN_GOPROXY", "https://proxy.invalid\nGOSUMDB=off")
	if _, err := isolatedGoEnvironment(t.TempDir()); err == nil {
		t.Fatal("isolatedGoEnvironment accepted an injected proxy environment line")
	}
	t.Setenv("SOW_CLEAN_GOPROXY", "https://proxy.example,direct")
	t.Setenv("SOW_CLEAN_GOSUMDB", "sum.golang.org\nGOPRIVATE=example.invalid")
	if _, err := isolatedGoEnvironment(t.TempDir()); err == nil {
		t.Fatal("isolatedGoEnvironment accepted an injected checksum environment line")
	}
	t.Setenv("SOW_CLEAN_GOSUMDB", "off")
	if _, err := isolatedGoEnvironment(t.TempDir()); err == nil {
		t.Fatal("isolatedGoEnvironment allowed checksum verification to be disabled")
	}
}

func TestValidateOutputLocationRejectsLexicalAndResolvedRepositoryDescendants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink ancestry fixture requires Unix semantics")
	}
	root := t.TempDir()
	for name, out := range map[string]string{
		"repository root": root,
		"lexical child":   filepath.Join(root, "release", "artifacts"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOutputLocation(root, out); err == nil || !strings.Contains(err.Error(), "outside repository") {
				t.Fatalf("validateOutputLocation(%s) = %v", out, err)
			}
		})
	}
	alias := filepath.Join(t.TempDir(), "repo-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := validateOutputLocation(root, filepath.Join(alias, "release", "artifacts")); err == nil || !strings.Contains(err.Error(), "resolved output") {
		t.Fatalf("resolved repository descendant error = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "release", "artifacts")
	if err := validateOutputLocation(root, outside); err != nil {
		t.Fatalf("external output rejected: %v", err)
	}
}

func TestCopyFileAtomicUsesOwnedTemporaryAndPreservesPreexistingTemp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source.tgz")
	destination := filepath.Join(root, "delivery.tgz")
	preexistingTemp := destination + ".tmp"
	if err := os.WriteFile(source, []byte("verified archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(preexistingTemp, []byte("owned by another process"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFileAtomic(source, destination, 0o644); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(destination); err != nil || string(raw) != "verified archive" {
		t.Fatalf("destination = %q, %v", raw, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("destination mode = %v, %v", info, err)
	}
	if raw, err := os.ReadFile(preexistingTemp); err != nil || string(raw) != "owned by another process" {
		t.Fatalf("pre-existing temporary changed = %q, %v", raw, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(root, ".delivery.tgz.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("owned temporary files were not cleaned: %v", leftovers)
	}
}

func writeFixture(t *testing.T, root, name, contents string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
