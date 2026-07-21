package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

func TestPublishProviderCredentialJSONIsStrict(t *testing.T) {
	var value objectStorageSecret
	if err := decodeSecretJSON([]byte(`{"access_key_id":"id","secret_access_key":"secret","session_token":"temporary"}`), &value); err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "id" || value.SecretAccessKey != "secret" || value.SessionToken != "temporary" {
		t.Fatalf("decoded %#v", value)
	}
	for _, input := range []string{
		`{"access_key_id":"id","secret_access_key":"secret","unknown":true}`,
		`{"access_key_id":"id","secret_access_key":"secret"}{}`,
		`not-json`,
	} {
		if err := decodeSecretJSON([]byte(input), &value); err == nil {
			t.Fatalf("unsafe credential document accepted: %s", input)
		}
	}
}

func TestDerivedPublicationStateRejectsSymlinkAndReplaysAtomically(t *testing.T) {
	stateRoot := t.TempDir()
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channel.json"), []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channel.json"), []byte("two")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(stateRoot, "generated", "channel.json"))
	if err != nil || string(body) != "two" {
		t.Fatalf("derived body=%q err=%v", body, err)
	}
	other := t.TempDir()
	badRoot := t.TempDir()
	if err := os.Symlink(other, filepath.Join(badRoot, "generated")); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(badRoot, filepath.Join("generated", "channel.json"), []byte("secret")); err == nil {
		t.Fatal("derived publication followed a symlinked directory")
	}
	if _, err := os.Stat(filepath.Join(other, "channel.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink escape wrote outside state root: %v", err)
	}
}

func TestDerivedStateWritePreservesLegacyDeterministicTemporary(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channel.json")
	body := []byte("new derived state")
	if err := os.MkdirAll(filepath.Join(stateRoot, "generated"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	legacy := filepath.Join(stateRoot, relative+".tmp-"+hex.EncodeToString(digest[:8]))
	canary := []byte("foreign deterministic temporary")
	if err := os.WriteFile(legacy, canary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, relative, body); err != nil {
		t.Fatalf("write derived state beside legacy temporary: %v", err)
	}
	current, err := os.ReadFile(legacy)
	if err != nil || !bytes.Equal(current, canary) {
		t.Fatalf("derived write deleted or changed legacy temporary body=%q err=%v", current, err)
	}
}

func TestDerivedStateWriteFailureCleanupPreservesConcurrentReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channel.json")
	if err := os.MkdirAll(filepath.Join(stateRoot, "generated"), 0o700); err != nil {
		t.Fatal(err)
	}
	var temporary string
	canary := []byte("foreign temporary replacement")
	previous := derivedStateWriteHook
	derivedStateWriteHook = func(current string) error {
		temporary = filepath.Join(stateRoot, current)
		if err := os.Rename(temporary, temporary+".test-original"); err != nil {
			return err
		}
		if err := os.WriteFile(temporary, canary, 0o600); err != nil {
			return err
		}
		return errors.New("inject derived state write failure")
	}
	t.Cleanup(func() { derivedStateWriteHook = previous })
	err := writeDerivedStateFile(stateRoot, relative, []byte("body"))
	if err == nil {
		t.Fatal("injected derived state write failure unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "temporary was replaced") {
		t.Fatalf("derived state cleanup failure was not reported: %v", err)
	}
	current, err := os.ReadFile(temporary)
	if err != nil || !bytes.Equal(current, canary) {
		t.Fatalf("failure cleanup deleted or changed replacement body=%q err=%v", current, err)
	}
	derivedStateWriteHook = nil
}

func TestDerivedStateWriteFailureCleansExactTemporary(t *testing.T) {
	stateRoot := t.TempDir()
	var temporary string
	previous := derivedStateWriteHook
	derivedStateWriteHook = func(current string) error {
		temporary = filepath.Join(stateRoot, current)
		return errors.New("inject exact derived state cleanup")
	}
	t.Cleanup(func() { derivedStateWriteHook = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channel.json"), []byte("body")); err == nil {
		t.Fatal("injected exact derived state failure unexpectedly succeeded")
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact derived state temporary remains after cleanup: %v", err)
	}
	derivedStateWriteHook = nil
}

func TestDerivedStateWriteInstallFailureCleansExactTemporary(t *testing.T) {
	stateRoot := t.TempDir()
	directory := filepath.Join(stateRoot, "generated")
	destination := filepath.Join(directory, "channel.json")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channel.json"), []byte("body")); err == nil {
		t.Fatal("derived state file unexpectedly replaced a destination directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "channel.json.tmp-") {
			t.Fatalf("derived state install failure retained temporary %s", entry.Name())
		}
	}
	info, err := os.Stat(destination)
	if err != nil || !info.IsDir() {
		t.Fatalf("derived state install failure changed destination directory: %v", err)
	}
}

func TestDerivedStateWriteRefusesConcurrentTemporaryReplacementBeforeInstall(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channel.json")
	destination := filepath.Join(stateRoot, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	var temporary string
	canary := []byte("foreign install replacement")
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(current string) error {
		temporary = filepath.Join(stateRoot, current)
		if err := os.Rename(temporary, temporary+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(temporary, canary, 0o600)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, relative, []byte("new canonical state")); err == nil {
		t.Fatal("derived state writer installed a replacement temporary")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, prior) {
		t.Fatalf("derived state destination changed body=%q err=%v", current, err)
	}
	replacement, err := os.ReadFile(temporary)
	if err != nil || !bytes.Equal(replacement, canary) {
		t.Fatalf("derived state replacement was deleted or changed body=%q err=%v", replacement, err)
	}
	derivedStateBeforeInstallHook = nil
}

func TestDerivedStateWriteRefusesInPlaceMutationWithRestoredMetadata(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channel.json")
	destination := filepath.Join(stateRoot, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("new canonical state")
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(current string) error {
		temporary := filepath.Join(stateRoot, current)
		identity, err := os.Stat(temporary)
		if err != nil {
			return err
		}
		if err := os.WriteFile(temporary, bytes.Repeat([]byte{'x'}, len(body)), 0o600); err != nil {
			return err
		}
		return os.Chtimes(temporary, identity.ModTime(), identity.ModTime())
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, relative, body); err == nil {
		t.Fatal("derived state writer installed in-place mutated bytes with restored metadata")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, prior) {
		t.Fatalf("derived state destination changed body=%q err=%v", current, err)
	}
	derivedStateBeforeInstallHook = nil
}

func TestDerivedStateWriteFreezesExpectedBodyBeforeHooks(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channel.json")
	destination := filepath.Join(stateRoot, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("new canonical state")
	mutated := bytes.Repeat([]byte{'m'}, len(body))
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(current string) error {
		temporary := filepath.Join(stateRoot, current)
		identity, err := os.Stat(temporary)
		if err != nil {
			return err
		}
		if err := os.WriteFile(temporary, mutated, 0o600); err != nil {
			return err
		}
		if err := os.Chtimes(temporary, identity.ModTime(), identity.ModTime()); err != nil {
			return err
		}
		copy(body, mutated)
		return nil
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, relative, body); err == nil {
		t.Fatal("derived state writer accepted hook-mutated expected bytes")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, prior) {
		t.Fatalf("derived state destination changed body=%q err=%v", current, err)
	}
	derivedStateBeforeInstallHook = nil
}

func TestDerivedStateWriteRejectsReplacedParentDirectoryBeforeInstall(t *testing.T) {
	stateRoot := t.TempDir()
	directory := filepath.Join(stateRoot, "generated")
	relative := filepath.Join("generated", "channel.json")
	destination := filepath.Join(stateRoot, relative)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement directory state")
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(string) error {
		if err := os.Rename(directory, directory+".test-original"); err != nil {
			return err
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		return os.WriteFile(destination, replacement, 0o600)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, relative, []byte("new canonical state")); err == nil {
		t.Fatal("derived state writer accepted a replaced parent directory coordinate")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, replacement) {
		t.Fatalf("replacement parent destination changed body=%q err=%v", current, err)
	}
	derivedStateBeforeInstallHook = nil
}

func TestDerivedStateWriteRejectsReplacedStateRootBeforeInstall(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	relative := "channel.json"
	destination := filepath.Join(stateRoot, relative)
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement state root")
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(string) error {
		if err := os.Rename(stateRoot, stateRoot+".test-original"); err != nil {
			return err
		}
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(destination, replacement, 0o600)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, relative, []byte("new canonical state")); err == nil {
		t.Fatal("derived state writer accepted a replaced state root coordinate")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, replacement) {
		t.Fatalf("replacement state-root destination changed body=%q err=%v", current, err)
	}
	derivedStateBeforeInstallHook = nil
}

func TestProviderBucketBaseURLAndBasicCredentialGate(t *testing.T) {
	got, err := providerBucketBaseURL("https://cos.ap-shanghai.myqcloud.com", "repo-1250000000")
	if err != nil || got != "https://repo-1250000000.cos.ap-shanghai.myqcloud.com" {
		t.Fatalf("base=%q err=%v", got, err)
	}
	for _, endpoint := range []string{"http://host", "https://host/path", "https://user@host", "https://host:8443"} {
		if _, err := providerBucketBaseURL(endpoint, "repo"); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if _, err := providerBucketBaseURL("https://host", "Bad_Bucket"); err == nil {
		t.Fatal("unsafe bucket accepted")
	}
	if _, err := basicVerificationCredentials("", "", true); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("missing Pro verification credential accepted: %v", err)
	}
	if credentials, err := basicVerificationCredentials("", "", false); err != nil || credentials != nil {
		t.Fatalf("optional basic = %#v err=%v", credentials, err)
	}
	if _, err := basicVerificationCredentials("user:name", "secret", true); err == nil {
		t.Fatal("colon-bearing Basic username accepted")
	}
}

func TestPublishTargetClientCarriesExplicitCheckpointFencedDeleteMode(t *testing.T) {
	t.Setenv("SOW_TEST_R2_STORAGE", `{"access_key_id":"test-access","secret_access_key":"test-secret"}`)
	t.Setenv("SOW_TEST_CF_CDN", `{"api_token":"test-token"}`)
	cfg := &config.Config{Targets: map[string]config.Target{
		"cf": {
			Storage: config.Storage{
				Kind: "r2", Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "test-bucket", Region: "auto",
				Credential: "env://SOW_TEST_R2_STORAGE", DeleteMode: config.StorageDeleteCheckpointFenced,
			},
			CDN: config.CDN{
				Kind: "cloudflare", BaseURL: "https://repo.example.invalid", BetaBaseURL: "https://beta.example.invalid",
				ZoneID: "test-zone", Credential: "env://SOW_TEST_CF_CDN",
			},
		},
	}}
	client, err := newPublishTargetClient(cfg, "cf", "latest", false)
	if err != nil {
		t.Fatal(err)
	}
	if client.deleteMode != config.StorageDeleteCheckpointFenced || client.r2 == nil || client.cos != nil {
		t.Fatalf("target client did not retain delete mode/provider: %#v", client)
	}
	if publisher, err := client.publisher(t.TempDir(), filepath.Join(t.TempDir(), "journal")); err != nil || publisher == nil {
		t.Fatalf("construct checkpoint-fenced publisher: publisher=%#v err=%v", publisher, err)
	}
}

func TestRemoteAuditTargetClientUsesOnlyStorageAuthority(t *testing.T) {
	t.Setenv("SOW_TEST_AUDIT_R2_STORAGE", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_AUDIT_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_AUDIT_COS_CDN", `this-is-deliberately-not-json`)
	cfg := &config.Config{Targets: map[string]config.Target{
		"cf": {
			Storage: config.Storage{
				Kind: "r2", Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "test-bucket", Region: "auto",
				Credential: "env://SOW_TEST_AUDIT_R2_STORAGE", DeleteMode: config.StorageDeleteCheckpointFenced,
			},
			CDN: config.CDN{
				Kind: "cloudflare", BaseURL: "https://repo.example.invalid", BetaBaseURL: "https://beta.example.invalid",
				ZoneID: "test-zone", Credential: "env://SOW_TEST_AUDIT_CF_CDN_DOES_NOT_EXIST",
			},
		},
		"cos": {
			Storage: config.Storage{
				Kind: "cos", Endpoint: "https://cos.ap-shanghai.myqcloud.com", Bucket: "repo-1250000000", Region: "ap-shanghai",
				Credential: "env://SOW_TEST_AUDIT_COS_STORAGE", DeleteMode: config.StorageDeleteCheckpointFenced,
			},
			CDN: config.CDN{
				Kind: "edgeone", BaseURL: "https://repo-cn.example.invalid", BetaBaseURL: "https://beta-cn.example.invalid",
				Distribution: "test-zone", Credential: "env://SOW_TEST_AUDIT_COS_CDN",
			},
		},
	}}
	for _, target := range []string{"cf", "cos"} {
		t.Run(target, func(t *testing.T) {
			client, err := newRemoteAuditTargetClient(cfg, target)
			if err != nil {
				t.Fatalf("construct storage-only %s audit client: %v", target, err)
			}
			if client.r2 != nil || client.cos != nil {
				t.Fatalf("storage-only %s client acquired a publication provider: %#v", target, client)
			}
			if target == "cf" && (client.r2Control == nil || client.cosControl != nil) {
				t.Fatalf("Cloudflare audit provider mismatch: %#v", client)
			}
			if target == "cos" && (client.cosControl == nil || client.r2Control != nil) {
				t.Fatalf("Tencent audit provider mismatch: %#v", client)
			}
			if publisher, err := client.publisher(t.TempDir(), filepath.Join(t.TempDir(), "journal")); err == nil || publisher != nil {
				t.Fatalf("storage-only %s client escalated into a publisher: publisher=%#v err=%v", target, publisher, err)
			}
		})
	}
}
