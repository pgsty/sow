package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/publish"
)

var bucketLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$`)

// publishProviderHTTPClient is nil in production. Tests replace it with a
// protocol-level transport so the real signing/provider code is exercised
// without contacting paid cloud resources.
var publishProviderHTTPClient *http.Client

type objectStorageSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type cloudflareCDNSecret struct {
	APIToken      string `json:"api_token"`
	BasicUser     string `json:"basic_username,omitempty"`
	BasicPassword string `json:"basic_password,omitempty"`
}

type tencentCDNSecret struct {
	SecretID      string `json:"secret_id"`
	SecretKey     string `json:"secret_key"`
	SessionToken  string `json:"session_token,omitempty"`
	BasicUser     string `json:"basic_username,omitempty"`
	BasicPassword string `json:"basic_password,omitempty"`
}

type publishTargetClient struct {
	name       publish.TargetName
	deleteMode string
	r2         *publish.R2CloudflareHTTP
	cos        *publish.COSEdgeOneHTTP
	r2Control  *publish.R2CloudflareControlHTTP
	cosControl *publish.COSControlHTTP
}

// newRemoteAuditTargetClient constructs the least-authority provider surface
// used by fsck. It resolves only object-storage credentials and therefore
// cannot purge a CDN or mutate Worker/EdgeOne configuration.
func newRemoteAuditTargetClient(cfg *config.Config, targetName string) (*publishTargetClient, error) {
	target, exists := cfg.Targets[targetName]
	if !exists {
		return nil, fmt.Errorf("publish target %q is not configured", targetName)
	}
	storageRaw, err := resolveSecret(target.Storage.Credential, "", false)
	if err != nil {
		return nil, err
	}
	defer clearSecret(storageRaw)
	var storage objectStorageSecret
	if err := decodeSecretJSON(storageRaw, &storage); err != nil {
		return nil, errors.New("decode target storage credential JSON")
	}
	objectBase, err := providerBucketBaseURL(target.Storage.Endpoint, target.Storage.Bucket)
	if err != nil {
		return nil, err
	}
	region := target.Storage.Region
	credentials := publish.S3Credentials{
		AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
		SessionToken: storage.SessionToken, Region: region,
	}
	switch targetName {
	case string(publish.TargetCloudflare):
		if region == "" {
			region = "auto"
			credentials.Region = region
		}
		if region != "auto" {
			return nil, errors.New("Cloudflare R2 signing region must be auto")
		}
		provider, err := publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
			Bucket: target.Storage.Bucket, ObjectBaseURL: objectBase, Credentials: credentials, Client: publishProviderHTTPClient,
		})
		if err != nil {
			return nil, err
		}
		return &publishTargetClient{name: publish.TargetCloudflare, deleteMode: target.Storage.DeleteMode, r2Control: provider}, nil
	case string(publish.TargetTencent):
		if region == "" {
			return nil, errors.New("Tencent COS storage.region is required")
		}
		provider, err := publish.NewCOSControlHTTP(publish.COSControlHTTPConfig{
			Bucket: target.Storage.Bucket, ObjectBaseURL: objectBase, Credentials: credentials, Client: publishProviderHTTPClient,
		})
		if err != nil {
			return nil, err
		}
		return &publishTargetClient{name: publish.TargetTencent, deleteMode: target.Storage.DeleteMode, cosControl: provider}, nil
	default:
		return nil, fmt.Errorf("unsupported publish target %q", targetName)
	}
}

func newPublishTargetClient(cfg *config.Config, targetName, viewName string, requireBasic bool) (*publishTargetClient, error) {
	target, exists := cfg.Targets[targetName]
	if !exists {
		return nil, fmt.Errorf("publish target %q is not configured", targetName)
	}
	storageRaw, err := resolveSecret(target.Storage.Credential, "", false)
	if err != nil {
		return nil, err
	}
	defer clearSecret(storageRaw)
	cdnRaw, err := resolveSecret(target.CDN.Credential, "", false)
	if err != nil {
		return nil, err
	}
	defer clearSecret(cdnRaw)
	var storage objectStorageSecret
	if err := decodeSecretJSON(storageRaw, &storage); err != nil {
		return nil, errors.New("decode target storage credential JSON")
	}
	objectBase, err := providerBucketBaseURL(target.Storage.Endpoint, target.Storage.Bucket)
	if err != nil {
		return nil, err
	}
	cdnBase := target.CDN.BaseURL
	if viewName == "beta" {
		cdnBase = target.CDN.BetaBaseURL
	}
	region := target.Storage.Region
	if targetName == string(publish.TargetCloudflare) {
		if region == "" {
			region = "auto"
		}
		if region != "auto" {
			return nil, errors.New("Cloudflare R2 signing region must be auto")
		}
		var cdn cloudflareCDNSecret
		if err := decodeSecretJSON(cdnRaw, &cdn); err != nil {
			return nil, errors.New("decode Cloudflare CDN credential JSON")
		}
		basic, err := basicVerificationCredentials(cdn.BasicUser, cdn.BasicPassword, requireBasic)
		if err != nil {
			return nil, err
		}
		provider, err := publish.NewR2CloudflareHTTP(publish.R2CloudflareHTTPConfig{
			Bucket:        target.Storage.Bucket,
			ObjectBaseURL: objectBase,
			CDNBaseURL:    cdnBase,
			Credentials: publish.S3Credentials{
				AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
				SessionToken: storage.SessionToken, Region: region,
			},
			ZoneID: target.CDN.ZoneID, APIToken: cdn.APIToken, VerificationBasic: basic, Client: publishProviderHTTPClient,
		})
		if err != nil {
			return nil, err
		}
		return &publishTargetClient{name: publish.TargetCloudflare, deleteMode: target.Storage.DeleteMode, r2: provider}, nil
	}
	if targetName != string(publish.TargetTencent) {
		return nil, fmt.Errorf("unsupported publish target %q", targetName)
	}
	if region == "" {
		return nil, errors.New("Tencent COS storage.region is required")
	}
	var cdn tencentCDNSecret
	if err := decodeSecretJSON(cdnRaw, &cdn); err != nil {
		return nil, errors.New("decode Tencent CDN credential JSON")
	}
	basic, err := basicVerificationCredentials(cdn.BasicUser, cdn.BasicPassword, requireBasic)
	if err != nil {
		return nil, err
	}
	provider, err := publish.NewCOSEdgeOneHTTP(publish.COSEdgeOneHTTPConfig{
		Bucket:        target.Storage.Bucket,
		ObjectBaseURL: objectBase,
		CDNBaseURL:    cdnBase,
		ObjectCredentials: publish.S3Credentials{
			AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
			SessionToken: storage.SessionToken, Region: region,
		},
		TencentCredentials: publish.TencentCredentials{
			SecretID: cdn.SecretID, SecretKey: cdn.SecretKey, Token: cdn.SessionToken,
		},
		ZoneID: target.CDN.Distribution, UnversionedBucketConfirmed: target.Storage.UnversionedBucketConfirmed,
		VerificationBasic: basic, Client: publishProviderHTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return &publishTargetClient{name: publish.TargetTencent, deleteMode: target.Storage.DeleteMode, cos: provider}, nil
}

func decodeSecretJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("credential JSON has trailing data")
	}
	return nil
}

func basicVerificationCredentials(username, password string, required bool) (*publish.BasicAuthCredentials, error) {
	if username == "" && password == "" {
		if required {
			return nil, errors.New("Pro publication requires basic_username and basic_password in the CDN credential JSON")
		}
		return nil, nil
	}
	if username == "" || password == "" || strings.ContainsAny(username, ":\x00\r\n") || strings.ContainsAny(password, "\x00\r\n") {
		return nil, errors.New("invalid CDN Basic verification credential")
	}
	return &publish.BasicAuthCredentials{Username: username, Password: password}, nil
}

// providerBucketBaseURL converts the schema's service endpoint plus bucket into
// the virtual-host bucket root signed by both real provider clients.
func providerBucketBaseURL(endpoint, bucket string) (string, error) {
	if !bucketLabelPattern.MatchString(bucket) {
		return "", errors.New("storage.bucket must be one DNS-safe bucket label")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("storage.endpoint must be a clean HTTPS service endpoint")
	}
	if parsed.Port() != "" {
		return "", errors.New("storage.endpoint must not use a custom port")
	}
	parsed.Host = bucket + "." + parsed.Hostname()
	parsed.Path = ""
	return parsed.String(), nil
}
