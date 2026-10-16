package managed

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func prepareRPMLeafExportFixture(t *testing.T, signed bool) (string, WorkspaceOptions, state.PackageObject, map[string][]byte) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	repo := config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm", Architectures: []string{"x86_64"}}}}
	if signed {
		private, _ := managedTestPrivateKey(t, "rpm-leaf")
		const environment = "SOW_TEST_RPM_LEAF_KEY"
		t.Setenv(environment, string(private))
		repo.Signing.RPM.Metadata.Key = "env://" + environment
	}
	cfg.Repositories["repo"] = repo
	cfg.Repositories["other"] = repo
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, objectErr := store.ListPackageObjects(ctx, []string{"el9"}, true)
	summary, summaryErr := store.Summary(ctx)
	signer, signerErr := store.GenerationViewSigner(ctx, summary.BuiltGeneration, "dists/el9/x86_64")
	closeErr := store.Close()
	if err := errors.Join(objectErr, summaryErr, signerErr, closeErr); err != nil || len(objects) != 1 {
		t.Fatalf("fixture objects=%#v err=%v", objects, err)
	}
	trust := map[string][]byte{}
	if signer.SignerIdentity != "none" {
		trust[signer.SignerIdentity] = signer.TrustedPublicKey
	}
	return root, opts, objects[0], trust
}

func TestExportRPMLeafCopyAndHardlinkExactWire(t *testing.T) {
	root, opts, object, trust := prepareRPMLeafExportFixture(t, false)
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest, err := store.GenerationManifest(ctx, before.BuiltGeneration)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		hardlink bool
	}{
		{name: "copy"},
		{name: "hardlink", hardlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(root, "exports-"+test.name)
			if test.name == "copy" {
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			result, err := ExportRPMLeaf(ctx, RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target, Hardlink: test.hardlink})
			if err != nil || result.Method != test.name || result.Packages != 1 || result.Generation != before.BuiltGeneration {
				t.Fatalf("export=%#v err=%v", result, err)
			}
			marker, err := VerifyRPMLeafExportStandalone(ctx, target, trust)
			if err != nil || marker.Method != test.name || marker.Signed || marker.SignerIdentity != "none" {
				t.Fatalf("marker=%#v err=%v", marker, err)
			}
			if sourceMarker, err := VerifyRPMLeafExportSourceBound(ctx, RPMLeafVerifySourceOptions{WorkspaceOptions: opts, Repository: "repo", Directory: target}); err != nil || sourceMarker != marker {
				t.Fatalf("source-bound marker=%#v err=%v", sourceMarker, err)
			}
			manifest, err := os.ReadFile(filepath.Join(target, "manifest.tsv"))
			if err != nil || !bytes.Contains(manifest, []byte(" "+object.PoolPath+"\n")) || bytes.Contains(manifest, []byte("manifest.tsv")) || bytes.Contains(manifest, []byte(".sow-export.json")) {
				t.Fatalf("manifest=%q err=%v", manifest, err)
			}
			sourceInfo, _ := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath)))
			exportInfo, _ := os.Stat(filepath.Join(target, filepath.FromSlash(object.PoolPath)))
			if os.SameFile(sourceInfo, exportInfo) != test.hardlink {
				t.Fatalf("SameFile=%t hardlink=%t", os.SameFile(sourceInfo, exportInfo), test.hardlink)
			}
		})
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	after, summaryErr := store.Summary(ctx)
	afterManifest, manifestErr := store.GenerationManifest(ctx, after.BuiltGeneration)
	closeErr := store.Close()
	if err := errors.Join(summaryErr, manifestErr, closeErr); err != nil || before != after || !reflect.DeepEqual(beforeManifest, afterManifest) {
		t.Fatalf("export changed repository state before=%#v after=%#v err=%v", before, after, err)
	}
}

func TestRPMLeafVerifierRejectsForeignMissingAndUnknownMarker(t *testing.T) {
	root, opts, _, trust := prepareRPMLeafExportFixture(t, false)
	target := filepath.Join(root, "export")
	if _, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target}); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(target, ".sow-export.json")
	original, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func() error
	}{
		{name: "foreign", mutate: func() error {
			return os.WriteFile(filepath.Join(target, "pool", "foreign.rpm"), []byte("foreign"), 0o644)
		}},
		{name: "foreign empty directory", mutate: func() error { return os.Mkdir(filepath.Join(target, "pool", "foreign-empty"), 0o755) }},
		{name: "missing marker", mutate: func() error { return os.Remove(markerPath) }},
		{name: "unknown marker", mutate: func() error {
			return os.WriteFile(markerPath, bytes.Replace(original, []byte(`{"arch"`), []byte(`{"extra":0,"arch"`), 1), 0o644)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.mutate(); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRPMLeafExportStandalone(context.Background(), target, trust); err == nil {
				t.Fatal("forged export verified")
			}
			_ = os.Remove(filepath.Join(target, "pool", "foreign.rpm"))
			_ = os.Remove(filepath.Join(target, "pool", "foreign-empty"))
			if err := os.WriteFile(markerPath, original, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
	marker, err := parseRPMLeafMarker(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	marker.ManifestSHA256 = strings.Repeat("0", 64)
	if _, err := verifyRPMLeafExportWithEvidence(context.Background(), target, trust, newPayloadEvidenceRegistry(), false, marker); err == nil {
		t.Fatal("pre-marker verifier accepted a mismatched manifest digest")
	}
}

func TestRPMLeafMarkerAllowsDigitLeadingDist(t *testing.T) {
	marker := RPMLeafExportMarker{
		Schema: rpmLeafExportSchema, Profile: rpmLeafExportProfile,
		RepositoryID: "00000000-0000-4000-8000-000000000001", Generation: 1,
		Dist: "9el", Arch: "x86_64", Method: "copy", SignerIdentity: "none",
		ManifestSHA256: strings.Repeat("0", 64),
	}
	wire, err := canonicalRPMLeafMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := parseRPMLeafMarker(wire); err != nil || parsed != marker {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestRPMLeafExportRejectsConfiguredFilesystemPublicationOverlap(t *testing.T) {
	root, options, _, _ := prepareRPMLeafExportFixture(t, false)
	endpoint, err := realDirectory(t.TempDir(), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "published/repo"
	publicationRoot := filepath.Join(endpoint, filepath.FromSlash(prefix))
	if err := os.MkdirAll(publicationRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = map[string]config.TargetConfig{"local": {
		Repository: "repo", Provider: "filesystem", Endpoint: (&url.URL{Scheme: "file", Path: endpoint}).String(), Prefix: prefix,
		PublicEndpoint: (&url.URL{Scheme: "file", Path: publicationRoot + string(filepath.Separator)}).String(), MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	writeManagedConfig(t, root, cfg)
	target := filepath.Join(publicationRoot, "leaf")
	if _, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: options, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "publication roots") {
		t.Fatalf("overlapping export error=%v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected export created target: %v", err)
	}
}

func TestRPMLeafManifestRejectsNoncanonicalSize(t *testing.T) {
	for _, size := range []string{"+1", "-0", "01"} {
		line := strings.Repeat("0", 64) + " " + size + " pool/p/pkg/pkg.rpm\n"
		if _, err := parseRPMLeafManifest([]byte(line)); err == nil {
			t.Fatalf("accepted noncanonical size %q", size)
		}
	}
}

func TestRPMLeafStandaloneVerifierRejectsNilContext(t *testing.T) {
	//lint:ignore SA1012 This test intentionally verifies the public nil-context rejection contract.
	if _, err := VerifyRPMLeafExportStandalone(nil, t.TempDir(), nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("nil context error=%v", err)
	}
}

func TestSignedRPMLeafUsesFrozenViewIdentityAndRejectsWrongTrust(t *testing.T) {
	root, opts, _, trust := prepareRPMLeafExportFixture(t, true)
	target := filepath.Join(root, "signed-export")
	result, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target})
	if err != nil || !result.Signed || len(trust[result.SignerIdentity]) == 0 {
		t.Fatalf("signed export=%#v err=%v", result, err)
	}
	if _, err := VerifyRPMLeafExportStandalone(context.Background(), target, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRPMLeafExportSourceBound(context.Background(), RPMLeafVerifySourceOptions{WorkspaceOptions: opts, Repository: "repo", Directory: target}); err != nil {
		t.Fatal(err)
	}
	wrongPrivate, _ := managedTestPrivateKey(t, "wrong-rpm-leaf")
	wrongIdentity, err := metadataIdentityFromMaterial(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRPMLeafExportStandalone(context.Background(), target, map[string][]byte{result.SignerIdentity: wrongIdentity.PublicKey}); err == nil {
		t.Fatal("signed export verified with wrong public key")
	}
	signature := filepath.Join(target, "repodata", "repomd.xml.asc")
	data, err := os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(signature, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRPMLeafExportStandalone(context.Background(), target, trust); err == nil {
		t.Fatal("tampered signature verified")
	}
}

func TestExportRPMLeafRejectsNonemptyAndCanonicalRoots(t *testing.T) {
	root, opts, _, _ := prepareRPMLeafExportFixture(t, false)
	nonempty := filepath.Join(root, "nonempty")
	if err := os.Mkdir(nonempty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonempty, "foreign"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(root, "real-empty")
	if err := os.Mkdir(realRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(root, "symlink-empty")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{nonempty, filepath.Join(root, "repo", "export"), filepath.Join(root, "other", "export"), filepath.Join(root, ".sow", "export"), symlinkRoot} {
		if _, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target}); !errors.Is(err, ErrRejected) {
			t.Fatalf("target %s error=%v", target, err)
		}
	}
}

func TestRPMLeafVerificationAuthenticatesEveryInvocation(t *testing.T) {
	root, opts, object, trust := prepareRPMLeafExportFixture(t, false)
	target := filepath.Join(root, "export")
	if _, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target}); err != nil {
		t.Fatal(err)
	}
	for _, sourceBound := range []bool{false, true, false, true} {
		ctx, collector := workmetrics.Ensure(context.Background())
		var err error
		if sourceBound {
			_, err = VerifyRPMLeafExportSourceBound(ctx, RPMLeafVerifySourceOptions{WorkspaceOptions: opts, Repository: "repo", Directory: target})
		} else {
			_, err = VerifyRPMLeafExportStandalone(ctx, target, trust)
		}
		if err != nil {
			t.Fatal(err)
		}
		if metrics := collector.Snapshot(); metrics.FullPackageReads != 1 || metrics.PayloadBytesRead != object.Size {
			t.Fatalf("independent verification must authenticate the payload once: %#v", metrics)
		}
	}
	path := filepath.Join(target, filepath.FromSlash(object.PoolPath))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, info.Mode()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRPMLeafExportStandalone(context.Background(), target, trust); err == nil {
		t.Fatal("independent verification accepted changed bytes with the original manifest and mtime")
	}
	if _, err := VerifyRPMLeafExportSourceBound(context.Background(), RPMLeafVerifySourceOptions{WorkspaceOptions: opts, Repository: "repo", Directory: target}); err == nil {
		t.Fatal("source-bound verification accepted changed bytes")
	}
}

func TestRPMLeafOutputEvidenceRebindsDescriptors(t *testing.T) {
	root, opts, object, trust := prepareRPMLeafExportFixture(t, false)
	for _, change := range []string{"stable", "replace_before_open", "link_during_wait", "rewrite_during_wait", "replace_during_wait", "foreign_directory", "cancel"} {
		t.Run(change, func(t *testing.T) {
			target := filepath.Join(root, change)
			if _, err := ExportRPMLeaf(context.Background(), RPMLeafExportOptions{WorkspaceOptions: opts, Repository: "repo", Dist: "el9", Arch: "x86_64", Directory: target}); err != nil {
				t.Fatal(err)
			}
			evidence := newPayloadEvidenceRegistry()
			if _, _, _, err := buildRPMLeafManifest(context.Background(), target, evidence); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(target, filepath.FromSlash(object.PoolPath))
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			held, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			before, err := snapshotRegularDescriptorIdentity(held)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, change+"-old")
			replace := func() {
				if err := os.Rename(path, alias); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
				restoreContentFixtureMTime(t, path, held, before)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &evidenceWaitContext{Context: base}
			ctx.onWait = func() {
				switch change {
				case "link_during_wait", "rewrite_during_wait":
					if change == "rewrite_during_wait" {
						body[len(body)-1] ^= 1
						if err := os.WriteFile(path, body, 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Link(path, alias); err != nil {
						t.Fatal(err)
					}
					restoreContentFixtureMTime(t, path, held, before)
				case "replace_during_wait":
					replace()
				case "foreign_directory":
					if err := os.Mkdir(filepath.Join(target, "pool", "foreign"), 0o755); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
				}
			}
			if change == "replace_before_open" {
				replace()
			}
			measured, collector := workmetrics.Ensure(ctx)
			_, err = verifyRPMLeafExportWithEvidence(measured, target, trust, evidence, true)
			wantErr := change == "rewrite_during_wait" || change == "replace_during_wait" || change == "foreign_directory" || change == "cancel"
			if (err != nil) != wantErr {
				t.Fatalf("changed output verification: err=%v wantErr=%t", err, wantErr)
			}
			if change != "replace_before_open" && !ctx.fired {
				t.Fatal("did not exercise the cached descriptor boundary")
			}
			if !wantErr {
				wantReads := int64(1)
				if change == "stable" {
					wantReads = 0
				}
				if metrics := collector.Snapshot(); metrics.FullPackageReads != wantReads || metrics.PayloadBytesRead != wantReads*object.Size {
					t.Fatalf("changed identity must authenticate again: %#v wantReads=%d", metrics, wantReads)
				}
			}
		})
	}
}
