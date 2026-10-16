package managed

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestDecodeRetainedEffectiveSigningAcceptsLegacyUnsignedDefault(t *testing.T) {
	snapshot, err := decodeRetainedEffectiveSigning("{}")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RPM.Packages.Mode != "never" || snapshot.RPM.Packages.Key != "" || len(snapshot.RPM.Packages.TrustedKeys) != 0 {
		t.Fatalf("legacy unsigned snapshot expanded incorrectly: %#v", snapshot)
	}
}

func TestRetainedRPMTrustPreservesEveryCertificateInBundle(t *testing.T) {
	var separate, combined bytes.Buffer
	writer, err := armor.Encode(&combined, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, name := range []string{"bundle-first", "bundle-second"} {
		private, fingerprint := managedTestPrivateKey(t, name)
		public, err := publicOpenPGPKeyMaterial(private)
		if err != nil {
			t.Fatal(err)
		}
		separate.Write(public)
		separate.WriteString("\r\n \t")
		entities, err := yumrepo.ParsePublicKeyring(public)
		if err != nil || len(entities) != 1 {
			t.Fatalf("public entity count=%d err=%v", len(entities), err)
		}
		if err := entities[0].Serialize(writer); err != nil {
			t.Fatal(err)
		}
		want = append(want, fingerprint)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "separate armor blocks", data: separate.Bytes()},
		{name: "multiple entities in one armor block", data: combined.Bytes()},
	} {
		t.Run(test.name, func(t *testing.T) {
			live, err := yumrepo.RPMPackageKeyringPrimaryFingerprints(test.data)
			if err != nil {
				t.Fatal(err)
			}
			for i := range live {
				live[i] = strings.ToUpper(live[i])
			}
			retained, err := retainedRPMSigningKeysFromMaterial(test.data)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, key := range retained {
				got = append(got, key.Fingerprint)
				if _, err := yumrepo.ParseRPMPackageKeyring(key.PublicKey); err != nil {
					t.Fatalf("retained certificate cannot form a verifier: %v", err)
				}
			}
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(live, want) {
				t.Fatalf("live=%v retained=%v want=%v", live, got, want)
			}
		})
	}
	malformed := append(append([]byte(nil), separate.Bytes()...), []byte("hidden trailing material")...)
	if _, err := retainedRPMSigningKeysFromMaterial(malformed); err == nil {
		t.Fatal("retained trust accepted incomplete input")
	}
}

func TestRPMTrustBundleSurvivesBuildRecoveryAndRotation(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		name := "normal build"
		if interrupted {
			name = "recovered build"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			root, ws, cfg := rpmPolicyCacheFixture(t, "fill")
			trustedPath := filepath.Join(root, "pgdg.asc")
			original, err := os.ReadFile(trustedPath)
			if err != nil {
				t.Fatal(err)
			}
			decoyPrivate, decoyFingerprint := managedTestPrivateKey(t, "bundle-first-decoy")
			decoy, err := publicOpenPGPKeyMaterial(decoyPrivate)
			if err != nil {
				t.Fatal(err)
			}
			// The package was signed by the second block. Truncating the bundle
			// must not leave a build that only its live trust ring can verify.
			bundle := bytes.Join([][]byte{decoy, original}, []byte("\n"))
			if err := os.WriteFile(trustedPath, bundle, 0600); err != nil {
				t.Fatal(err)
			}
			crash := errors.New("stop after frozen bundle build")
			built, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2, Fault: func(point string) error {
				if interrupted && point == "build.staged" {
					return crash
				}
				return nil
			}})
			if interrupted {
				if !errors.Is(err, crash) {
					t.Fatalf("frozen build=%+v err=%v", built, err)
				}
				if err := os.Remove(trustedPath); err != nil {
					t.Fatal(err)
				}
				store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				recoveryErr := recoverDistOperations(ctx, root, "repo", store)
				detail, detailErr := store.GetOperation(ctx, built.Operation)
				closeErr := store.Close()
				if err := errors.Join(recoveryErr, detailErr, closeErr); err != nil {
					t.Fatal(err)
				}
				if detail.Operation.State != state.OperationDone {
					t.Fatalf("recovered operation=%+v", detail.Operation)
				}
				if err := os.WriteFile(trustedPath, bundle, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2})
			if err != nil || !checked.ReadyToCopy {
				t.Fatalf("bundle build check=%+v err=%v", checked, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			keys, keysErr := store.ListRPMSigningKeys(ctx)
			summary, summaryErr := store.Summary(ctx)
			closeErr := store.Close()
			if err := errors.Join(keysErr, summaryErr, closeErr); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, key := range keys {
				found = found || key.Fingerprint == decoyFingerprint
			}
			if len(keys) != 3 || !found {
				t.Fatalf("retained %d certificates, second trusted certificate retained=%t", len(keys), found)
			}
			if _, err := RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: ws, Repository: "repo", Generation: summary.BuiltGeneration}); err != nil {
				t.Fatal(err)
			}
			repo := cfg.Repositories["repo"]
			repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "never"}
			cfg.Repositories["repo"] = repo
			writeManagedConfig(t, root, cfg)
			if err := os.Remove(trustedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "wrong.asc")); err != nil {
				t.Fatal(err)
			}
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2}); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRetainedGeneration(ctx, RetainVerifyOptions{WorkspaceOptions: ws, Repository: "repo", Generation: summary.BuiltGeneration}); err != nil {
				t.Fatalf("retained generation lost trust after rotation: %v", err)
			}
		})
	}
}
