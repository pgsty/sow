package cli

import (
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
