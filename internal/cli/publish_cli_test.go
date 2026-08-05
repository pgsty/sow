package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type protocolObject struct {
	body []byte
	sha  string
	etag string
}

type cloudProtocolTransport struct {
	mutex              sync.Mutex
	objects            map[string]protocolObject
	cosObjects         map[string]protocolObject
	cdnOverrides       map[string]protocolObject
	puts               int
	copies             int
	deletes            int
	putKeys            []string
	purges             int
	purgeURLs          []string
	cdnGets            int
	cdnURLs            []string
	edgePreflights     int
	basicGets          int
	tokenGets          int
	listCalls          int
	objectGets         int
	headCalls          int
	mutateOnSecondList bool
	mutateETagOnGet    map[string]string
	staleCDNOnPurge    bool
	failCOSObjectPUTs  int
	etagSerial         int
	edgeOneJobID       string
}

type rawPublicCDNTransport struct {
	base     http.RoundTripper
	canaries atomic.Int32
}

func (transport *rawPublicCDNTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/.sow/gated/.sow-confidentiality-preflight" {
		transport.canaries.Add(1)
		return protocolResponse(request, http.StatusNotFound, "NoSuchKey\n", map[string]string{
			"Cache-Control": "public, max-age=1800",
		}), nil
	}
	return transport.base.RoundTrip(request)
}

func newCloudProtocolTransport() *cloudProtocolTransport {
	return &cloudProtocolTransport{objects: make(map[string]protocolObject), cosObjects: make(map[string]protocolObject), cdnOverrides: make(map[string]protocolObject), mutateETagOnGet: make(map[string]string)}
}

func (transport *cloudProtocolTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	switch request.URL.Host {
	case "repo-bucket.storage.test":
		return transport.objectResponse(request)
	case "repo-1250000000.cos.ap-shanghai.myqcloud.com":
		return transport.objectResponse(request)
	case "api.cloudflare.com":
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/purge_cache") || request.Header.Get("Authorization") != "Bearer cf-api-token" {
			return protocolResponse(request, http.StatusBadRequest, "bad purge", nil), nil
		}
		transport.purges++
		var requestBody struct {
			Files []string `json:"files"`
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			return nil, err
		}
		transport.purgeURLs = append(transport.purgeURLs, requestBody.Files...)
		if !transport.staleCDNOnPurge {
			for _, value := range requestBody.Files {
				delete(transport.cdnOverrides, value)
			}
		}
		return protocolResponse(request, http.StatusOK, `{"success":true,"errors":[],"result":{"id":"zone-1"}}`, map[string]string{
			"Content-Type": "application/json",
			"CF-Ray":       fmt.Sprintf("cf-ray-%d", transport.purges),
		}), nil
	case "repo.test", "beta.test":
		return transport.cdnResponse(request)
	case "repo-cn.test", "beta-cn.test":
		return transport.cdnResponse(request)
	case "teo.tencentcloudapi.com":
		if !strings.HasPrefix(request.Header.Get("Authorization"), "TC3-HMAC-SHA256 ") {
			return protocolResponse(request, http.StatusUnauthorized, "", nil), nil
		}
		switch request.Header.Get("X-TC-Action") {
		case "CreatePurgeTask":
			transport.purges++
			var body struct {
				Targets []string `json:"Targets"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				return nil, err
			}
			transport.purgeURLs = append(transport.purgeURLs, body.Targets...)
			if !transport.staleCDNOnPurge {
				for _, value := range body.Targets {
					delete(transport.cdnOverrides, value)
				}
			}
			transport.edgeOneJobID = fmt.Sprintf("job-%d", transport.purges)
			return protocolResponse(request, http.StatusOK, fmt.Sprintf(`{"Response":{"JobId":%q,"FailedList":[],"RequestId":%q}}`, transport.edgeOneJobID, "create-"+transport.edgeOneJobID), nil), nil
		case "DescribePurgeTasks":
			return protocolResponse(request, http.StatusOK, fmt.Sprintf(`{"Response":{"Tasks":[{"JobId":%q,"Status":"success","CreateTime":"2026-07-14T00:00:00Z","UpdateTime":"2026-07-14T00:00:01Z"}],"RequestId":%q}}`, transport.edgeOneJobID, "describe-"+transport.edgeOneJobID), nil), nil
		default:
			return protocolResponse(request, http.StatusBadRequest, "", nil), nil
		}
	default:
		return nil, fmt.Errorf("unexpected protocol host %s", request.URL.Host)
	}
}

func (transport *cloudProtocolTransport) objectResponse(request *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		return protocolResponse(request, http.StatusUnauthorized, "unsigned", nil), nil
	}
	objects := transport.objects
	metadataHeader := "X-Amz-Meta-Sow-Sha256"
	if strings.Contains(request.URL.Host, ".cos.") {
		objects = transport.cosObjects
		metadataHeader = "X-Cos-Meta-Sow-Sha256"
		if request.Method == http.MethodGet && strings.Contains(request.URL.RawQuery, "versioning") {
			return protocolResponse(request, http.StatusOK, `<VersioningConfiguration/>`, map[string]string{"Content-Type": "application/xml"}), nil
		}
	}
	if request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "2" {
		transport.listCalls++
		if transport.mutateOnSecondList && transport.listCalls == 2 {
			objects["drift/appeared"] = protocolObject{body: []byte("drift"), sha: publishDigest([]byte("drift")), etag: `"drift"`}
		}
		if request.URL.Query().Get("encoding-type") != "url" || request.URL.Query().Get("max-keys") != "1000" {
			return protocolResponse(request, http.StatusBadRequest, "bad list request", nil), nil
		}
		start := 0
		if token := request.URL.Query().Get("continuation-token"); token != "" {
			if !strings.HasPrefix(token, "offset-") {
				return protocolResponse(request, http.StatusBadRequest, "bad token", nil), nil
			}
			var err error
			start, err = strconv.Atoi(strings.TrimPrefix(token, "offset-"))
			if err != nil {
				return nil, err
			}
		}
		keys := make([]string, 0, len(objects))
		for key := range objects {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		end := min(start+2, len(keys))
		if start < 0 || start > end {
			return protocolResponse(request, http.StatusBadRequest, "bad offset", nil), nil
		}
		var document strings.Builder
		document.WriteString(`<ListBucketResult><EncodingType>url</EncodingType>`)
		fmt.Fprintf(&document, "<IsTruncated>%t</IsTruncated>", end < len(keys))
		for _, key := range keys[start:end] {
			object := objects[key]
			fmt.Fprintf(&document, "<Contents><Key>%s</Key><Size>%d</Size><ETag>%s</ETag></Contents>",
				html.EscapeString(url.PathEscape(key)), len(object.body), html.EscapeString(object.etag))
		}
		if end < len(keys) {
			fmt.Fprintf(&document, "<NextContinuationToken>offset-%d</NextContinuationToken>", end)
		}
		document.WriteString(`</ListBucketResult>`)
		return protocolResponse(request, http.StatusOK, document.String(), map[string]string{"Content-Type": "application/xml"}), nil
	}
	key := strings.TrimPrefix(request.URL.Path, "/")
	object, exists := objects[key]
	switch request.Method {
	case http.MethodGet:
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		if etag, mutate := transport.mutateETagOnGet[key]; mutate {
			object.etag = etag
			objects[key] = object
			delete(transport.mutateETagOnGet, key)
		}
		transport.objectGets++
		return protocolResponse(request, http.StatusOK, string(object.body), map[string]string{"ETag": object.etag, metadataHeader: object.sha}), nil
	case http.MethodHead:
		transport.headCalls++
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		response := protocolResponse(request, http.StatusOK, "", map[string]string{"ETag": object.etag, metadataHeader: object.sha})
		response.ContentLength = int64(len(object.body))
		return response, nil
	case http.MethodPut:
		if strings.Contains(request.URL.Host, ".cos.") && transport.failCOSObjectPUTs > 0 {
			transport.failCOSObjectPUTs--
			return protocolResponse(request, http.StatusServiceUnavailable, "injected COS PUT failure", nil), nil
		}
		transport.putKeys = append(transport.putKeys, key)
		if (request.Header.Get("If-None-Match") == "*" || strings.EqualFold(request.Header.Get("X-Cos-Forbid-Overwrite"), "true")) && exists {
			return protocolResponse(request, http.StatusPreconditionFailed, "", nil), nil
		}
		if expected := request.Header.Get("If-Match"); expected != "" && (!exists || object.etag != expected) {
			return protocolResponse(request, http.StatusPreconditionFailed, "", nil), nil
		}
		copySource := request.Header.Get("X-Amz-Copy-Source")
		if copySource == "" {
			copySource = request.Header.Get("X-Cos-Copy-Source")
		}
		if copySource != "" {
			copySource = strings.TrimPrefix(copySource, "/")
			if slash := strings.IndexByte(copySource, '/'); slash >= 0 {
				copySource = copySource[slash+1:]
			}
			copySource, _ = url.PathUnescape(copySource)
			source, sourceExists := objects[copySource]
			if !sourceExists {
				return protocolResponse(request, http.StatusNotFound, `<Error><Code>NoSuchKey</Code></Error>`, nil), nil
			}
			sourceMatch := request.Header.Get("X-Amz-Copy-Source-If-Match")
			if sourceMatch == "" {
				sourceMatch = request.Header.Get("X-Cos-Copy-Source-If-Match")
			}
			if sourceMatch != source.etag {
				return protocolResponse(request, http.StatusPreconditionFailed, `<Error><Code>PreconditionFailed</Code></Error>`, nil), nil
			}
			transport.etagSerial++
			etag := fmt.Sprintf(`"etag-%d"`, transport.etagSerial)
			objects[key] = protocolObject{body: append([]byte(nil), source.body...), sha: request.Header.Get(metadataHeader), etag: etag}
			transport.copies++
			return protocolResponse(request, http.StatusOK, `<CopyObjectResult><ETag>`+html.EscapeString(etag)+`</ETag></CopyObjectResult>`, map[string]string{"Content-Type": "application/xml"}), nil
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		transport.etagSerial++
		etag := fmt.Sprintf(`"etag-%d"`, transport.etagSerial)
		objects[key] = protocolObject{body: body, sha: request.Header.Get(metadataHeader), etag: etag}
		transport.puts++
		return protocolResponse(request, http.StatusOK, "", map[string]string{"ETag": etag}), nil
	case http.MethodDelete:
		expected := request.Header.Get("If-Match")
		if expected == "" {
			return protocolResponse(request, http.StatusBadRequest, "missing If-Match", nil), nil
		}
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		if object.etag != expected {
			return protocolResponse(request, http.StatusPreconditionFailed, "", nil), nil
		}
		delete(objects, key)
		if !strings.HasPrefix(key, ".sow/probes/conditional-delete/") {
			transport.deletes++
		}
		return protocolResponse(request, http.StatusNoContent, "", nil), nil
	default:
		return protocolResponse(request, http.StatusMethodNotAllowed, "", nil), nil
	}
}

func (transport *cloudProtocolTransport) cdnResponse(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/.sow/gated/.sow-confidentiality-preflight" {
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" ||
			request.Header.Get("Cookie") != "" || request.Header.Get("Accept-Encoding") != "identity" ||
			request.Header.Get("Cache-Control") != "no-store, no-cache, max-age=0" || request.Header.Get("Pragma") != "no-cache" {
			return protocolResponse(request, http.StatusBadRequest, "invalid confidentiality preflight", nil), nil
		}
		transport.edgePreflights++
		return protocolResponse(request, http.StatusNotFound, "not_found\n", map[string]string{
			"Content-Type":           "text/plain; charset=utf-8",
			"Cache-Control":          "private, no-store, max-age=0",
			"X-Content-Type-Options": "nosniff",
			"X-SOW-Edge-Contract":    config.EdgeRuntimeSchema,
		}), nil
	}
	transport.cdnGets++
	transport.cdnURLs = append(transport.cdnURLs, request.URL.String())
	if override, exists := transport.cdnOverrides[request.URL.String()]; exists {
		return protocolResponse(request, http.StatusOK, string(override.body), nil), nil
	}
	objects := transport.objects
	if strings.Contains(request.URL.Host, "-cn.test") {
		objects = transport.cosObjects
	}
	key := strings.TrimPrefix(request.URL.Path, "/")
	pro, proPrefix := false, ""
	if strings.HasPrefix(key, "pro/v1/") {
		parts := strings.SplitN(key, "/", 4)
		if len(parts) != 4 {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		switch parts[2] {
		case "basic":
			username, password, ok := request.BasicAuth()
			if !ok || username != "verifier" || password != "verify-secret" {
				return protocolResponse(request, http.StatusUnauthorized, "", nil), nil
			}
			transport.basicGets++
		case verifyTestProToken:
			if request.Header.Get("Authorization") != "" {
				return protocolResponse(request, http.StatusBadRequest, "", nil), nil
			}
			transport.tokenGets++
		default:
			return protocolResponse(request, http.StatusUnauthorized, "", nil), nil
		}
		pro, proPrefix, key = true, "/pro/v1/"+parts[2], parts[3]
		if candidate, exists := objects[".sow/gated/"+key]; exists {
			return protocolResponse(request, http.StatusOK, string(candidate.body), nil), nil
		}
	}
	if strings.HasPrefix(key, "_sow/v1/mirrorlist/") {
		if !pro {
			if object, exists := objects[key]; exists {
				return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
			}
		}
		parts := strings.Split(key, "/")
		if len(parts) != 7 {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		arch := strings.TrimSuffix(parts[6], ".txt")
		channelKey := fmt.Sprintf(".sow/channels/%s/%s/%s/%s.json", parts[3], parts[4], parts[5], arch)
		channel, exists := objects[channelKey]
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		var document struct {
			Generation string `json:"generation"`
			LegacyRoot string `json:"legacy_root"`
		}
		if err := json.Unmarshal(channel.body, &document); err != nil {
			return nil, err
		}
		route := path.Join(strings.TrimPrefix(proPrefix, "/"), "_sow/v1/g", document.Generation, document.LegacyRoot)
		clientURL, err := config.CanonicalRouteURL("https://"+request.URL.Host, route, true)
		if err != nil {
			return nil, err
		}
		return protocolResponse(request, http.StatusOK, clientURL+"\n", nil), nil
	}
	if strings.HasPrefix(key, "_sow/v1/snapshots/") {
		parts := strings.SplitN(strings.TrimPrefix(key, "_sow/v1/snapshots/"), "/", 2)
		if !pro || len(parts) != 2 {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		snapshotID, remainder := parts[0], parts[1]
		route, exists := objects[".sow/snapshots/"+snapshotID+".json"]
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		var pointer struct {
			Generation string `json:"generation"`
		}
		if err := json.Unmarshal(route.body, &pointer); err != nil {
			return nil, err
		}
		if remainder == "_route.json" {
			return protocolResponse(request, http.StatusOK, string(route.body), nil), nil
		}
		kind, repositoryPath, found := strings.Cut(remainder, "/")
		if !found {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		var originKey string
		switch kind {
		case "apt":
			if strings.Contains(repositoryPath, "/dists/") {
				originKey = ".sow/gated/generations/" + pointer.Generation + "/apt/" + repositoryPath
			} else {
				originKey = ".sow/gated/" + repositoryPath
				if _, ok := objects[originKey]; !ok {
					originKey = repositoryPath
				}
			}
		case "yum":
			if strings.Contains(repositoryPath, "/repodata/") {
				originKey = ".sow/gated/generations/" + pointer.Generation + "/yum/" + repositoryPath
			} else {
				originKey = ".sow/gated/snapshots/" + snapshotID + "/yum/" + repositoryPath
			}
		case "assets":
			originKey = ".sow/gated/snapshots/" + snapshotID + "/asset/" + repositoryPath
		}
		object, exists := objects[originKey]
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
	}
	if strings.HasPrefix(key, "_sow/v1/a/") {
		parts := strings.SplitN(strings.TrimPrefix(key, "_sow/v1/a/"), "/", 2)
		if len(parts) != 2 {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		prefix := ".sow/generations/"
		if pro {
			prefix = ".sow/gated/generations/"
		}
		object, exists := objects[prefix+parts[0]+"/apt/"+parts[1]]
		if !exists {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
	}
	if strings.HasPrefix(key, "_sow/v1/g/") {
		parts := strings.SplitN(strings.TrimPrefix(key, "_sow/v1/g/"), "/", 2)
		if len(parts) != 2 {
			return protocolResponse(request, http.StatusNotFound, "", nil), nil
		}
		payloadIndex := strings.Index(parts[1], "/repodata/")
		if payloadIndex >= 0 {
			prefix := ".sow/generations/"
			if pro {
				prefix = ".sow/gated/generations/"
			}
			legacy, payload := parts[1][:payloadIndex], parts[1][payloadIndex+1:]
			object, exists := objects[prefix+parts[0]+"/yum/"+legacy+"/"+payload]
			if !exists {
				return protocolResponse(request, http.StatusNotFound, "", nil), nil
			}
			return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
		}
		packageIndex := strings.Index(parts[1], "/Packages/")
		if packageIndex >= 0 {
			legacy, payload := parts[1][:packageIndex], parts[1][packageIndex+1:]
			packageKey := legacy + "/" + payload
			if pro {
				if object, exists := objects[".sow/gated/"+packageKey]; exists {
					return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
				}
			}
			if object, exists := objects[packageKey]; exists {
				return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
			}
		}
	}
	if request.URL.Host == "beta.test" || request.URL.Host == "beta-cn.test" {
		if candidate, exists := objects[".sow/beta/"+key]; exists {
			return protocolResponse(request, http.StatusOK, string(candidate.body), nil), nil
		}
	}
	object, exists := objects[key]
	if !exists {
		return protocolResponse(request, http.StatusNotFound, "", nil), nil
	}
	return protocolResponse(request, http.StatusOK, string(object.body), nil), nil
}

func TestPublishCLIRejectsGatedCanonicalLeafInPublicLatestBeforeNetwork(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("public-before-corruption\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	latestRef, err := state.ViewRef("latest", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	latestCommit, exists, err := canonical.Ref(latestRef)
	if err != nil || !exists {
		t.Fatalf("latest ref exists=%v err=%v", exists, err)
	}
	latestPath, err := state.ViewPath("latest", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := canonical.OpenPathAt(latestCommit, latestPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := views.NewReader(reader).Next()
	if closeErr := reader.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	entry.Pool = "gated"
	var invalid bytes.Buffer
	if err := views.WriteEntry(&invalid, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "invalid-latest.tsv")
	if err := os.WriteFile(stage, invalid.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidCommit, changed, err := canonical.InstallPaths(map[string]string{latestPath: stage}, "inject invalid public latest leaf")
	if err != nil || !changed {
		t.Fatalf("inject invalid commit=%s changed=%v err=%v", invalidCommit, changed, err)
	}
	if err := canonical.AdvanceRef(latestRef, latestCommit, invalidCommit, false); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets")
	if code != ExitVerification || !strings.Contains(stderr, "closure violation") {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	puts, purges, cdnGets := transport.puts, transport.purges, transport.cdnGets
	putAttempts := len(transport.putKeys)
	purgeURLs := len(transport.purgeURLs)
	transport.mutex.Unlock()
	if puts != 0 || putAttempts != 0 || purges != 0 || purgeURLs != 0 || cdnGets != 0 {
		t.Fatalf("confidentiality failure reached network puts=%d attempts=%d purges=%d urls=%d cdn_gets=%d", puts, putAttempts, purges, purgeURLs, cdnGets)
	}
}

func TestPublishCLIDeduplicatesRepeatedTargetFlags(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("deduplicated-target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--target", "cf", "--config", configPath, "--repo", "assets")
	if code != ExitOK || strings.Count(stdout, "target=cf view=beta") != 1 || strings.Count(stdout, "status=published") != 1 {
		t.Fatalf("deduplicated publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	checkpointBody := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	checkpoint, err := publish.DecodeCheckpoint(checkpointBody)
	if err != nil || checkpoint.Generation != 1 {
		t.Fatalf("checkpoint=%#v err=%v body=%s", checkpoint, err, checkpointBody)
	}
}

func TestPublishCLIAssetPublicPathProjectsPhysicalTreeToServingRoot(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := strings.Replace(publishAssetConfig,
		"    path: pkg\n    default_pool: public\n    asset:\n      kind: release",
		"    path: asset/bootstrap\n    default_pool: public\n    asset:\n      kind: bootstrap\n      public_path: pkg", 1)
	if configText == publishAssetConfig {
		t.Fatal("asset projection fixture replacement did not match")
	}
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "tool.tar.gz")
	if err := os.WriteFile(input, []byte("projected-bootstrap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "tool.tar.gz"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	for _, key := range []string{".sow/beta/pkg/tool.tar.gz", "pkg/tool.tar.gz"} {
		if _, exists := transport.objects[key]; !exists {
			t.Fatalf("projected object %s is missing", key)
		}
	}
	for _, key := range []string{".sow/beta/asset/bootstrap/tool.tar.gz", "asset/bootstrap/tool.tar.gz"} {
		if _, leaked := transport.objects[key]; leaked {
			t.Fatalf("physical source path leaked as remote object %s", key)
		}
	}
	for _, url := range []string{"https://beta.test/pkg/tool.tar.gz", "https://repo.test/pkg/tool.tar.gz"} {
		if !contains(transport.cdnURLs, url) {
			t.Fatalf("projected CDN verification %s is missing; urls=%v", url, transport.cdnURLs)
		}
	}
}

func TestPublishCLIStableUsesGatedNamespaceAndScopedBasicVerification(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := strings.Replace(publishAssetConfig, "id: assets\n    type: asset\n    path: pkg\n    default_pool: public", "id: assets\n    type: asset\n    path: proprietary\n    default_pool: gated", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "secret.bin")
	if err := os.WriteFile(input, []byte("licensed-bits"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "secret.bin"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("gated add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "assets"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("stable publish code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	transport.mutex.Lock()
	_, gated := transport.objects[".sow/gated/proprietary/secret.bin"]
	_, leaked := transport.objects["proprietary/secret.bin"]
	basicGets := transport.basicGets
	edgePreflights := transport.edgePreflights
	puts := transport.puts
	transport.mutex.Unlock()
	if !gated || leaked || edgePreflights != 1 || basicGets == 0 || puts == 0 {
		t.Fatalf("stable route gated=%v leaked=%v edge_preflights=%d basic_gets=%d puts=%d", gated, leaked, edgePreflights, basicGets, puts)
	}
}

func TestPublishCLIRejectsRawPublicCustomDomainBeforeGatedMutation(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := strings.Replace(publishAssetConfig, "id: assets\n    type: asset\n    path: pkg\n    default_pool: public", "id: assets\n    type: asset\n    path: proprietary\n    default_pool: gated", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "secret.bin")
	if err := os.WriteFile(input, []byte("licensed-bits"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	rawDomain := &rawPublicCDNTransport{base: protocol}
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: rawDomain}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "secret.bin"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("gated add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "assets"}, &stdout, &stderr)
	if code == ExitOK || !strings.Contains(stderr.String(), "confidential edge denial canary") {
		t.Fatalf("raw custom domain publish code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	protocol.mutex.Lock()
	puts, copies, deletes, purges := protocol.puts, protocol.copies, protocol.deletes, protocol.purges
	putKeys := append([]string(nil), protocol.putKeys...)
	protocol.mutex.Unlock()
	if rawDomain.canaries.Load() != 1 || puts != 0 || copies != 0 || deletes != 0 || purges != 0 || len(putKeys) != 0 {
		t.Fatalf("raw custom domain crossed remote mutation boundary canaries=%d puts=%d copies=%d deletes=%d purges=%d keys=%v", rawDomain.canaries.Load(), puts, copies, deletes, purges, putKeys)
	}
}

func TestPublishCLIPersistsSuccessfulTargetWhenSiblingCredentialIsUnavailable(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets")
	if code != ExitPartialPublish || !strings.Contains(stdout, "target=cf") || !strings.Contains(stdout, "status=published") || !strings.Contains(stdout, "target=cos") || !strings.Contains(stdout, "failed-before-saga") {
		t.Fatalf("partial code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	cfRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(cfRef); err != nil || !exists {
		t.Fatalf("successful cf remote ref exists=%v err=%v", exists, err)
	}
	cosRef, _ := state.RemoteRef("cos", "latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(cosRef); err != nil || exists {
		t.Fatalf("failed cos remote ref exists=%v err=%v", exists, err)
	}
}

func TestPublishCLICommitsBothIndependentTargetsInOneInvocation(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("4.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets")
	if code != ExitOK || strings.Count(stdout, "status=published") != 2 {
		t.Fatalf("dual publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	for _, target := range []string{"cf", "cos"} {
		ref, _ := state.RemoteRef(target, "latest", "assets", "all", "all")
		if _, exists, err := canonical.Ref(ref); err != nil || !exists {
			t.Fatalf("target %s remote ref exists=%v err=%v", target, exists, err)
		}
		if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", target, "generation.json")); err != nil {
			t.Fatalf("target %s generation: %v", target, err)
		}
	}
	cosInventory, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cos", "inventory.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	lockKey, _ := publish.GenerationLockKey(1)
	if !strings.Contains(string(cosInventory), lockKey+"\t") {
		t.Fatalf("COS inventory omitted create-only generation lock %s", lockKey)
	}
	transport.mutex.Lock()
	_, cfCheckpoint := transport.objects[publish.CheckpointKey]
	_, cosCheckpoint := transport.cosObjects[publish.CheckpointKey]
	transport.mutex.Unlock()
	if !cfCheckpoint || !cosCheckpoint {
		t.Fatalf("remote checkpoints cf=%v cos=%v", cfCheckpoint, cosCheckpoint)
	}
}

func TestPublishCLIDefaultViewsStopsFailedTargetAndContinuesSibling(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("ordered-target-failure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	transport.failCOSObjectPUTs = 1
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, promotion := range [][2]string{{"beta", "latest"}, {"latest", "stable"}} {
		if code, stdout, stderr := run("promote", promotion[0], promotion[1], "--config", configPath, "--repo", "assets"); code != ExitOK {
			t.Fatalf("promote %v code=%d stdout=%s stderr=%s", promotion, code, stdout, stderr)
		}
	}

	code, stdout, stderr := run("publish", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitPartialPublish {
		t.Fatalf("default publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, view := range []string{"beta", "latest", "stable"} {
		if !strings.Contains(stdout, "target=cf view="+view) || !strings.Contains(stdout, "target=cf view="+view+" generation=") {
			t.Fatalf("healthy target did not publish %s: %s", view, stdout)
		}
		if strings.Contains(stdout, "target=cos view="+view+" generation=2") || strings.Contains(stdout, "target=cos view="+view+" generation=3") {
			t.Fatalf("failed target advanced beyond its first failed view: %s", stdout)
		}
	}
	if !strings.Contains(stdout, "target=cos view=beta") || !strings.Contains(stdout, "target=cos view=beta generation=1") || !strings.Contains(stdout, "status=failed") {
		t.Fatalf("failed target identity is missing: %s", stdout)
	}
	transport.mutex.Lock()
	cfCheckpointBody := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	cosCheckpointBody := append([]byte(nil), transport.cosObjects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	cfCheckpoint, err := publish.DecodeCheckpoint(cfCheckpointBody)
	if err != nil || cfCheckpoint.Generation != 3 || cfCheckpoint.IntentView != "stable" {
		t.Fatalf("healthy target checkpoint=%#v err=%v body=%s", cfCheckpoint, err, cfCheckpointBody)
	}
	if len(cosCheckpointBody) != 0 {
		cosCheckpoint, decodeErr := publish.DecodeCheckpoint(cosCheckpointBody)
		if decodeErr == nil && cosCheckpoint.Generation > 1 {
			t.Fatalf("failed target advanced checkpoint=%#v", cosCheckpoint)
		}
	}
}

func TestPublishCLIDefaultSnapshotRecoveryFailureDoesNotBlockSibling(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "snapshot.txt")
	if err := os.WriteFile(input, []byte("snapshot-recovery-isolation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "release"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, promotion := range [][2]string{{"beta", "latest"}, {"latest", "stable"}} {
		if code, stdout, stderr := run("promote", promotion[0], promotion[1], "--config", configPath, "--repo", "assets"); code != ExitOK {
			t.Fatalf("promote %v code=%d stdout=%s stderr=%s", promotion, code, stdout, stderr)
		}
	}
	snapshotID, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("snapshot promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "default-snapshot-isolation-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationSnapshot(t.Context(), cfg, canonical, pool, cfg.Repos, snapshotID, txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cos", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	publisher := publish.NewCOSEdgeOnePublisher(publication.client.cos, publish.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhaseLocked && !injected {
			injected = true
			return errors.New("injected interrupted snapshot")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected interrupted snapshot") {
		t.Fatalf("snapshot interruption err=%v", err)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.failCOSObjectPUTs = 1
	transport.mutex.Unlock()

	code, stdout, stderr := run("publish", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitPartialPublish || !strings.Contains(stdout, "target=cos view=snapshot status=failed-recovery") {
		t.Fatalf("default snapshot recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, view := range []string{"beta", "latest", "stable"} {
		if !strings.Contains(stdout, "target=cf view="+view+" generation=") {
			t.Fatalf("healthy target missed %s after sibling snapshot failure: %s", view, stdout)
		}
		if strings.Contains(stdout, "target=cos view="+view+" generation=") {
			t.Fatalf("failed snapshot target advanced %s: %s", view, stdout)
		}
	}
	if !strings.Contains(stdout, "target=cf view=snapshot snapshot="+snapshotID) || !strings.Contains(stdout, "status=published") {
		t.Fatalf("healthy target did not publish retained snapshot: %s", stdout)
	}
	transport.mutex.Lock()
	cfCheckpointBody := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	cosCheckpointBody := append([]byte(nil), transport.cosObjects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	cfCheckpoint, err := publish.DecodeCheckpoint(cfCheckpointBody)
	if err != nil || cfCheckpoint.Generation != 4 || cfCheckpoint.IntentView != "snapshot" || cfCheckpoint.IntentSnapshot != snapshotID {
		t.Fatalf("healthy target checkpoint=%#v err=%v body=%s", cfCheckpoint, err, cfCheckpointBody)
	}
	if len(cosCheckpointBody) != 0 {
		cosCheckpoint, decodeErr := publish.DecodeCheckpoint(cosCheckpointBody)
		if decodeErr != nil || cosCheckpoint.Generation > 1 || cosCheckpoint.IntentView != "snapshot" || cosCheckpoint.IntentSnapshot != snapshotID {
			t.Fatalf("failed target checkpoint advanced=%#v err=%v body=%s", cosCheckpoint, decodeErr, cosCheckpointBody)
		}
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	for generation := uint64(2); generation <= 4; generation++ {
		key, keyErr := publish.GenerationKey(generation)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		if _, exists := transport.cosObjects[key]; exists {
			t.Fatalf("failed snapshot target created later generation %d", generation)
		}
	}
}

func TestPublishCLIDefaultRecoversExactSnapshotBeforeViewsAndRetainsOthersAfter(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "snapshot.txt")
	if err := os.WriteFile(input, []byte("exact-snapshot-recovery-order\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "release"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, promotion := range [][2]string{{"beta", "latest"}, {"latest", "stable"}} {
		if code, stdout, stderr := run("promote", promotion[0], promotion[1], "--config", configPath, "--repo", "assets"); code != ExitOK {
			t.Fatalf("promote %v code=%d stdout=%s stderr=%s", promotion, code, stdout, stderr)
		}
	}
	recoverySnapshot, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	retainedSnapshot, err := views.SnapshotID("extra", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", recoverySnapshot, "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("snapshot %s promote code=%d stdout=%s stderr=%s", recoverySnapshot, code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	stableRef, _ := state.ViewRef("stable", "assets", "all", "all")
	stablePath, _ := state.ViewPath("stable", "assets", "all", "all")
	stableCommit, exists, err := canonical.Ref(stableRef)
	if err != nil || !exists {
		t.Fatalf("stable ref exists=%v err=%v", exists, err)
	}
	stableReader, err := canonical.OpenPathAt(stableCommit, stablePath)
	if err != nil {
		t.Fatal(err)
	}
	stableBody, readErr := io.ReadAll(stableReader)
	closeErr := stableReader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	retainedDir, err := newTransactionDir(cfg.StatePath(), "retained-snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(retainedDir)
	retainedStage := filepath.Join(retainedDir, "retained-snapshot.tsv")
	if err := os.WriteFile(retainedStage, stableBody, 0o600); err != nil {
		t.Fatal(err)
	}
	retainedPath, _ := state.SnapshotPath(retainedSnapshot, "assets", "all", "all")
	retainedRef, _ := state.SnapshotRef(retainedSnapshot, "assets", "all", "all")
	if _, changed, err := canonical.Apply(t.Context(), "test-retained-snapshot", "create unrelated retained snapshot", map[string]string{retainedPath: retainedStage}, []state.RefUpdate{{Name: retainedRef, Immutable: true}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("create retained snapshot changed=%v err=%v", changed, err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "default-exact-snapshot-order-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationSnapshot(t.Context(), cfg, canonical, pool, cfg.Repos, recoverySnapshot, txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	publisher := publish.NewR2CloudflarePublisher(publication.client.r2, publish.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhaseLocked && !injected {
			injected = true
			return errors.New("injected exact snapshot interruption")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected exact snapshot interruption") {
		t.Fatalf("snapshot interruption err=%v", err)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run("publish", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK {
		t.Fatalf("default publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	recoveredLine := "target=cf view=snapshot snapshot=" + recoverySnapshot + " generation=1"
	betaLine := "target=cf view=beta generation=2"
	stableLine := "target=cf view=stable generation=4"
	retainedLine := "target=cf view=snapshot snapshot=" + retainedSnapshot
	recoveredAt, betaAt := strings.Index(stdout, recoveredLine), strings.Index(stdout, betaLine)
	stableAt, retainedAt := strings.Index(stdout, stableLine), strings.Index(stdout, retainedLine)
	if recoveredAt < 0 || betaAt < 0 || stableAt < 0 || retainedAt < 0 || !(recoveredAt < betaAt && betaAt < stableAt && stableAt < retainedAt) {
		t.Fatalf("publication order recovery=%d beta=%d stable=%d retained=%d stdout=%s", recoveredAt, betaAt, stableAt, retainedAt, stdout)
	}
	for _, expected := range []string{
		"target=cf view=latest generation=3",
		"target=cf view=snapshot snapshot=" + recoverySnapshot + " status=unchanged",
		"target=cf view=snapshot snapshot=" + retainedSnapshot + " generation=5",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("missing ordered publication %q: %s", expected, stdout)
		}
	}
	transport.mutex.Lock()
	checkpointBody := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	checkpoint, err := publish.DecodeCheckpoint(checkpointBody)
	if err != nil || checkpoint.Generation != 5 || checkpoint.IntentView != "snapshot" || checkpoint.IntentSnapshot != retainedSnapshot {
		t.Fatalf("final checkpoint=%#v err=%v body=%s", checkpoint, err, checkpointBody)
	}
}

func TestPublishCLIAssetRemoveDeletesBothServingRoutesAndRestoreReputs(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("asset-delete-contract\n")
	input := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"},
		{"publish", "--view", "beta", "--config", configPath, "--repo", "assets", "--workers", "2"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"publish", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	sha := publishDigest(body)
	archiveKey := "objects/sha256/" + sha
	transport.mutex.Lock()
	for _, objects := range []map[string]protocolObject{transport.objects, transport.cosObjects} {
		direct, exists := objects["pkg/latest"]
		if !exists {
			transport.mutex.Unlock()
			t.Fatal("initial latest serving object is missing")
		}
		// Simulate a zero-byte-adopted legacy object: the old target manifest
		// is the ownership evidence, while live deletion must GET+hash because
		// origin HEAD has no sow-sha256 metadata.
		direct.sha = ""
		objects["pkg/latest"] = direct
		if _, exists := objects[archiveKey]; !exists {
			transport.mutex.Unlock()
			t.Fatalf("mutable asset archive %s is missing", archiveKey)
		}
	}
	deletesBefore, getsBefore := transport.deletes, transport.objectGets
	transport.mutex.Unlock()

	if code, stdout, stderr := run("rm", "latest", "--view", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK || !strings.Contains(stdout, "removed view=latest entries=1") {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	transport.cdnOverrides["https://repo.test/pkg/latest"] = protocolObject{body: []byte("stale cached asset")}
	transport.staleCDNOnPurge = true
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "still returns a successful response") {
		t.Fatalf("stale CDN delete code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.deletes != deletesBefore+1 {
		transport.mutex.Unlock()
		t.Fatalf("failed CDN verification did not apply exact origin delete before=%d after=%d", deletesBefore, transport.deletes)
	}
	transport.staleCDNOnPurge = false
	transport.mutex.Unlock()
	code, stdout, stderr = run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("stale CDN replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("publish", "--view", "latest", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("independent COS delete code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.deletes != deletesBefore+2 || transport.objectGets < getsBefore+2 {
		transport.mutex.Unlock()
		t.Fatalf("delete protocol deletes=%d/%d origin_gets=%d/%d", deletesBefore, transport.deletes, getsBefore, transport.objectGets)
	}
	for target, objects := range map[string]map[string]protocolObject{"cf": transport.objects, "cos": transport.cosObjects} {
		if _, exists := objects["pkg/latest"]; exists {
			transport.mutex.Unlock()
			t.Fatalf("target %s retained direct latest asset", target)
		}
		if _, exists := objects[".sow/beta/pkg/latest"]; !exists {
			transport.mutex.Unlock()
			t.Fatalf("target %s lost unrelated beta intent", target)
		}
		if _, exists := objects[archiveKey]; !exists {
			transport.mutex.Unlock()
			t.Fatalf("target %s deleted content-addressed restore archive", target)
		}
	}
	deletesAfter := transport.deletes
	transport.mutex.Unlock()

	for _, rawURL := range []string{"https://repo.test/pkg/latest", "https://repo-cn.test/pkg/latest"} {
		response, err := publishProviderHTTPClient.Get(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("deleted URL %s status=%d", rawURL, response.StatusCode)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || strings.Count(stdout, "status=unchanged") != 2 {
		t.Fatalf("delete replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.deletes != deletesAfter {
		transport.mutex.Unlock()
		t.Fatalf("unchanged replay repeated delete before=%d after=%d", deletesAfter, transport.deletes)
	}
	transport.mutex.Unlock()

	for _, target := range []string{"cf", "cos"} {
		code, stdout, stderr := run("publish", "--restore-generation", "2", "--target", target, "--config", configPath, "--workers", "2")
		if code != ExitOK || !strings.Contains(stdout, "status=complete") {
			t.Fatalf("restore target=%s code=%d stdout=%s stderr=%s", target, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	for target, objects := range map[string]map[string]protocolObject{"cf": transport.objects, "cos": transport.cosObjects} {
		object, exists := objects["pkg/latest"]
		if !exists || !bytes.Equal(object.body, body) {
			t.Fatalf("target %s restore did not re-PUT exact asset: %#v", target, object)
		}
	}
}

func TestPublishCLIAPTByHashRetentionDeletesBothTargetsAcrossStaggeredPublishes(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cfAndCOS := `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(aptByHashCLIConfig, "targets: {}\n", cfAndCOS, 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	_, keyPath := writeMaterializeSigningKey(t, root)
	packages := []string{
		writeRetentionDEB(t, root, "1.0.0"),
		writeRetentionDEB(t, root, "2.0.0"),
		writeRetentionDEB(t, root, "3.0.0"),
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	readLedger := func() aptrepo.ByHashLedger {
		file, err := os.Open(filepath.Join(root, ".sow", "state", "retention", "apt-by-hash", "views", "beta", "deb-retention", "jammy.json"))
		if err != nil {
			t.Fatal(err)
		}
		ledger, decodeErr := aptrepo.DecodeByHashLedger(file)
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil {
			t.Fatal(errors.Join(decodeErr, closeErr))
		}
		return ledger
	}
	add := func(packagePath string) {
		if code, stdout, stderr := run("add", packagePath, "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", packagePath, code, stdout, stderr)
		}
	}
	publishTargets := func(targets ...string) {
		args := []string{"publish", "--view", "beta", "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		for _, target := range targets {
			args = append(args, "--target", target)
		}
		if code, stdout, stderr := run(args...); code != ExitOK || strings.Count(stdout, "status=published") != len(targets) {
			t.Fatalf("publish %v code=%d stdout=%s stderr=%s", targets, code, stdout, stderr)
		}
	}

	add(packages[0])
	first := readLedger().Generations[0]
	publishTargets("cf", "cos")
	add(packages[1])
	publishTargets("cf", "cos")
	transport.mutex.Lock()
	for _, relative := range first.Paths {
		key := path.Join(".sow/beta/apt/retention", relative)
		if _, exists := transport.objects[key]; !exists {
			transport.mutex.Unlock()
			t.Fatalf("cf missing first generation key before retention: %s", key)
		}
		if _, exists := transport.cosObjects[key]; !exists {
			transport.mutex.Unlock()
			t.Fatalf("cos missing first generation key before retention: %s", key)
		}
	}
	transport.mutex.Unlock()

	add(packages[2])
	current := readLedger()
	if len(current.Generations) != 2 {
		t.Fatalf("current retained generations=%d want=2", len(current.Generations))
	}
	retained := make(map[string]struct{})
	for _, generation := range current.Generations {
		for _, relative := range generation.Paths {
			retained[relative] = struct{}{}
		}
	}
	transport.mutex.Lock()
	deletesBefore := transport.deletes
	transport.mutex.Unlock()
	// Publish cf first. Its canonical remote-state commit must leave the Git
	// ledger tombstone usable by the independently lagging COS target.
	publishTargets("cf")
	transport.mutex.Lock()
	deletesAfterCF := transport.deletes
	transport.mutex.Unlock()
	if deletesAfterCF != deletesBefore+len(first.Paths) {
		t.Fatalf("cf by-hash deletes=%d want=%d", deletesAfterCF-deletesBefore, len(first.Paths))
	}
	publishTargets("cos")
	transport.mutex.Lock()
	deletesAfterCOS := transport.deletes
	for target, objects := range map[string]map[string]protocolObject{"cf": transport.objects, "cos": transport.cosObjects} {
		for _, relative := range first.Paths {
			key := path.Join(".sow/beta/apt/retention", relative)
			if _, exists := objects[key]; exists {
				transport.mutex.Unlock()
				t.Fatalf("target %s retained expired by-hash key %s", target, key)
			}
		}
		for relative := range retained {
			key := path.Join(".sow/beta/apt/retention", relative)
			if _, exists := objects[key]; !exists {
				transport.mutex.Unlock()
				t.Fatalf("target %s lost retained by-hash key %s", target, key)
			}
		}
	}
	for _, purgeURL := range transport.purgeURLs {
		if strings.Contains(purgeURL, "/by-hash/") {
			transport.mutex.Unlock()
			t.Fatalf("immutable by-hash deletion expanded CDN purge: %s", purgeURL)
		}
	}
	transport.mutex.Unlock()
	if deletesAfterCOS != deletesAfterCF+len(first.Paths) {
		t.Fatalf("cos by-hash deletes=%d want=%d", deletesAfterCOS-deletesAfterCF, len(first.Paths))
	}

	if code, stdout, stderr := run("publish", "--view", "beta", "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK || strings.Count(stdout, "status=unchanged") != 2 {
		t.Fatalf("retention replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	deletesAfterReplay := transport.deletes
	transport.mutex.Unlock()
	if deletesAfterReplay != deletesAfterCOS {
		t.Fatalf("unchanged replay repeated by-hash deletes before=%d after=%d", deletesAfterCOS, deletesAfterReplay)
	}
}

func TestPublishCLIRecoversRemoteCheckpointCommittedBeforeLocalRemoteRef(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var output, errorOutput bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"}, &output, &errorOutput); code != ExitOK {
		t.Fatalf("add code=%d stderr=%s", code, errorOutput.String())
	}
	output.Reset()
	errorOutput.Reset()
	if code := Main([]string{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"}, &output, &errorOutput); code != ExitOK {
		t.Fatalf("promote code=%d stderr=%s", code, errorOutput.String())
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-crash-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, cfg.Repos, "latest", txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := publication.client.publisher(root, filepath.Join(cfg.StatePath(), "publish-journal"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Run(t.Context(), publication.request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("remote-only publication result=%#v err=%v", result, err)
	}
	remoteRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(remoteRef); err != nil || exists {
		t.Fatalf("remote ref advanced before local commit exists=%v err=%v", exists, err)
	}
	transport.mutex.Lock()
	putOffset := len(transport.putKeys)
	checkpointBefore := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	putsBefore, purgesBefore, _ := transport.counts()
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	errorOutput.Reset()
	code := Main([]string{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"}, &output, &errorOutput)
	putsAfter, purgesAfter, _ := transport.counts()
	transport.mutex.Lock()
	repairPuts := append([]string(nil), transport.putKeys[putOffset:]...)
	checkpointAfter := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	generationKey, err := publish.GenerationKey(1)
	if err != nil {
		t.Fatal(err)
	}
	if code != ExitOK || !strings.Contains(output.String(), "status=published") || putsAfter != putsBefore+1 || purgesAfter != purgesBefore+1 ||
		len(repairPuts) != 2 || repairPuts[0] != "pkg/latest" || repairPuts[1] != generationKey || !bytes.Equal(checkpointBefore, checkpointAfter) {
		t.Fatalf("recovery code=%d stdout=%s stderr=%s puts=%d/%d repair_puts=%v purges=%d/%d checkpoint_changed=%t", code, output.String(), errorOutput.String(), putsBefore, putsAfter, repairPuts, purgesBefore, purgesAfter, !bytes.Equal(checkpointBefore, checkpointAfter))
	}
	if remoteCommit, exists, err := canonical.Ref(remoteRef); err != nil || !exists || remoteCommit.IsZero() {
		t.Fatalf("recovered remote ref=%s exists=%v err=%v", remoteCommit, exists, err)
	}
}

func TestPublishCLIRestoresHistoricalPublishedIntentThroughSaga(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("release-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	sourceGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || sourceGeneration.Generation != 1 {
		t.Fatalf("source generation=%#v exists=%v err=%v", sourceGeneration, exists, err)
	}
	var sourceLatest publish.RefState
	for _, ref := range sourceGeneration.Refs {
		if strings.HasPrefix(ref.Name, "refs/sow/views/beta/") {
			sourceLatest = ref
		}
	}
	if sourceLatest.Name == "" {
		t.Fatal("source generation has no latest ref")
	}

	if err := os.WriteFile(input, []byte("release-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	if got := string(transport.objects[".sow/beta/pkg/latest"].body); got != "release-two\n" {
		transport.mutex.Unlock()
		t.Fatalf("generation two mutable object=%q", got)
	}
	putsBefore, purgesBefore, getsBefore := transport.puts, transport.purges, transport.cdnGets
	transport.mutex.Unlock()

	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "source_generation=1") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	restoredGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || restoredGeneration.Generation != 3 || restoredGeneration.ParentGeneration != 2 {
		t.Fatalf("restored generation=%#v exists=%v err=%v", restoredGeneration, exists, err)
	}
	remoteRef, _ := state.RemoteRef("cf", "beta", "assets", "all", "all")
	remoteCommit, exists, err := canonical.Ref(remoteRef)
	if err != nil || !exists || remoteCommit.String() != sourceLatest.Commit {
		t.Fatalf("restored remote ref=%s want=%s exists=%v err=%v", remoteCommit, sourceLatest.Commit, exists, err)
	}
	transport.mutex.Lock()
	if got := string(transport.objects[".sow/beta/pkg/latest"].body); got != "release-one\n" {
		transport.mutex.Unlock()
		t.Fatalf("restored mutable object=%q", got)
	}
	putsAfter, purgesAfter, getsAfter := transport.puts, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	if putsAfter <= putsBefore || purgesAfter <= purgesBefore || getsAfter <= getsBefore {
		t.Fatalf("restore skipped saga side effects puts=%d/%d purges=%d/%d gets=%d/%d", putsBefore, putsAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}
	localServingBody, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "pkg", "latest"))
	if err != nil || string(localServingBody) != "release-two\n" {
		t.Fatalf("restore rewrote current local beta tree body=%q err=%v", localServingBody, err)
	}
	restoreRoot := filepath.Join(root, ".sow", "materialized", "restores", "cf", "00000000000000000001", "beta")
	if _, err := os.Stat(restoreRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed restore retained hidden reconstruction tree %s: %v", restoreRoot, err)
	}
	auditPath := filepath.Join(root, ".sow", "state", "remotes", "cf", "restores", "00000000000000000003.json")
	auditBody, err := os.ReadFile(auditPath)
	if err != nil || !bytes.Contains(auditBody, []byte(`"source_generation":1`)) || !bytes.Contains(auditBody, []byte(`"source_plan_sha256":"`)) || !bytes.Contains(auditBody, []byte(sourceLatest.Commit)) {
		t.Fatalf("restore audit=%s err=%v", auditBody, err)
	}

	code, stdout, stderr = run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("idempotent restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if transport.puts != putsAfter || transport.purges != purgesAfter || transport.cdnGets != getsAfter {
		t.Fatalf("idempotent restore repeated side effects puts=%d/%d purges=%d/%d gets=%d/%d", putsAfter, transport.puts, purgesAfter, transport.purges, getsAfter, transport.cdnGets)
	}
}

func TestPublishRestoreGenerationRequiresOneTargetAndNoSelectors(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"publish", "--restore-generation", "1", "--config", configPath},
		{"publish", "--restore-generation", "1", "--target", "cf", "--view", "latest", "--config", configPath},
		{"publish", "--restore-generation", "1", "--target", "cf", "--repo", "assets", "--config", configPath},
		{"publish", "--restore-generation", "0", "--target", "cf", "--config", configPath},
	} {
		var stdout, stderr bytes.Buffer
		if code := Main(args, &stdout, &stderr); code != ExitUsage {
			t.Fatalf("args=%v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
}

type assetRestoreFixture struct {
	root       string
	configPath string
	transport  *cloudProtocolTransport
	canonical  *state.Store
	cfg        *config.Config
	sourceRef  publish.RefState
	sourceSHA  string
}

func newAssetRestoreFixture(t *testing.T) assetRestoreFixture {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Main(args, &stdout, &stderr); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("restore-fixture-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest")
	run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	canonical := state.New(filepath.Join(root, ".sow"))
	first, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || first.Generation != 1 {
		t.Fatalf("first generation=%#v exists=%v err=%v", first, exists, err)
	}
	var sourceRef publish.RefState
	for _, ref := range first.Refs {
		if strings.HasPrefix(ref.Name, "refs/sow/views/beta/") {
			sourceRef = ref
		}
	}
	if sourceRef.Name == "" {
		t.Fatal("first generation has no beta ref")
	}
	viewPath, _ := state.ViewPath("beta", "assets", "all", "all")
	reader, err := canonical.OpenPathAt(plumbing.NewHash(sourceRef.Commit), viewPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := views.NewReader(reader).Next()
	if closeErr := reader.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if err := os.WriteFile(input, []byte("restore-fixture-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace")
	run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	return assetRestoreFixture{root: root, configPath: configPath, transport: transport, canonical: canonical, cfg: cfg, sourceRef: sourceRef, sourceSHA: entry.SHA256}
}

func TestPublishRestoreGenerationResumesAfterPurgedCrash(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	historical, err := loadHistoricalTargetPublication(fixture.canonical, "cf", 1)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(fixture.cfg.StatePath(), "restore-crash-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	client, err := newPublishTargetClient(fixture.cfg, "cf", "beta", false)
	if err != nil {
		t.Fatal(err)
	}
	inspection := filepath.Join(txDir, "inspect")
	if err := os.Mkdir(inspection, 0o700); err != nil {
		t.Fatal(err)
	}
	observation, err := observeRemoteTarget(t.Context(), fixture.canonical, client, "cf", inspection)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareHistoricalPublication(t.Context(), fixture.cfg, fixture.cfg, fixture.canonical, pool, fixture.cfg.Repos, "cf", historical, observation.parent, txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	head, err := fixture.canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), fixture.cfg, fixture.canonical, fixture.cfg.Repos, prepared, "cf", head, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(publication.request.TransactionID, "from-00000000000000000001") {
		t.Fatalf("restore transaction does not bind source generation: %s", publication.request.TransactionID)
	}
	injected := false
	publisher := publish.NewR2CloudflarePublisher(publication.client.r2, publish.DirectorySource{Root: fixture.root}, filepath.Join(fixture.cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhasePurged && !injected {
			injected = true
			return errors.New("injected restore crash after purge")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected restore crash after purge") {
		t.Fatalf("restore crash err=%v", err)
	}
	local, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || local.Generation != 2 {
		t.Fatalf("local target advanced during crash generation=%#v exists=%v err=%v", local, exists, err)
	}
	fixture.transport.mutex.Lock()
	putsBefore, purgesBefore := fixture.transport.puts, fixture.transport.purges
	fixture.transport.mutex.Unlock()
	var wrongStdout, wrongStderr bytes.Buffer
	wrongCode := Main([]string{"publish", "--view", "beta", "--target", "cf", "--config", fixture.configPath, "--repo", "assets", "--workers", "2"}, &wrongStdout, &wrongStderr)
	if wrongCode != ExitConflict || !strings.Contains(wrongStderr.String(), "--restore-generation 1 --target cf") || !strings.Contains(wrongStderr.String(), publication.request.TransactionID) {
		t.Fatalf("wrong recovery diagnosis code=%d stdout=%s stderr=%s", wrongCode, wrongStdout.String(), wrongStderr.String())
	}
	fixture.transport.mutex.Lock()
	if fixture.transport.puts != putsBefore || fixture.transport.purges != purgesBefore {
		fixture.transport.mutex.Unlock()
		t.Fatalf("wrong recovery path mutated remote puts=%d/%d purges=%d/%d", putsBefore, fixture.transport.puts, purgesBefore, fixture.transport.purges)
	}
	fixture.transport.mutex.Unlock()
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath, "--workers", "2"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "generation=3") || !strings.Contains(stdout.String(), "status=complete") {
		t.Fatalf("restore recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	fixture.transport.mutex.Lock()
	defer fixture.transport.mutex.Unlock()
	if fixture.transport.purges != purgesBefore+1 {
		t.Fatalf("restore recovery did not repurge replayed mutable closure before=%d after=%d", purgesBefore, fixture.transport.purges)
	}
	if got := string(fixture.transport.objects[".sow/beta/pkg/latest"].body); got != "restore-fixture-one\n" {
		t.Fatalf("restore recovery object=%q", got)
	}
}

func TestPublishRestoreGenerationFailsClosedWhenHistoricalCASIsMissing(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(fixture.sourceSHA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pool.ObjectPath(digest)); err != nil {
		t.Fatal(err)
	}
	fixture.transport.mutex.Lock()
	putsBefore, purgesBefore, getsBefore := fixture.transport.puts, fixture.transport.purges, fixture.transport.cdnGets
	fixture.transport.mutex.Unlock()
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath, "--workers", "2"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "materialize historical intent") {
		t.Fatalf("missing CAS restore code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	restoreRoot := filepath.Join(fixture.root, ".sow", "materialized", "restores", "cf", "00000000000000000001", "beta")
	if _, err := os.Stat(restoreRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore retained hidden reconstruction tree %s: %v", restoreRoot, err)
	}
	fixture.transport.mutex.Lock()
	defer fixture.transport.mutex.Unlock()
	if fixture.transport.puts != putsBefore || fixture.transport.purges != purgesBefore || fixture.transport.cdnGets != getsBefore {
		t.Fatalf("missing CAS reached remote mutation puts=%d/%d purges=%d/%d gets=%d/%d", putsBefore, fixture.transport.puts, purgesBefore, fixture.transport.purges, getsBefore, fixture.transport.cdnGets)
	}
}

func TestPublishRestoreGenerationFailsClosedOnConfigurationDriftBeforeNetwork(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	configuration, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	configuration = bytes.Replace(configuration, []byte("state: {}"), []byte("state: {cas_history_commits: 33}"), 1)
	if err := os.WriteFile(fixture.configPath, configuration, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.transport.mutex.Lock()
	putsBefore, purgesBefore, getsBefore := fixture.transport.puts, fixture.transport.purges, fixture.transport.cdnGets
	fixture.transport.mutex.Unlock()
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath, "--workers", "2"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "config_sha256") {
		t.Fatalf("configuration drift restore code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	fixture.transport.mutex.Lock()
	defer fixture.transport.mutex.Unlock()
	if fixture.transport.puts != putsBefore || fixture.transport.purges != purgesBefore || fixture.transport.cdnGets != getsBefore {
		t.Fatalf("configuration drift reached network puts=%d/%d purges=%d/%d gets=%d/%d", putsBefore, fixture.transport.puts, purgesBefore, fixture.transport.purges, getsBefore, fixture.transport.cdnGets)
	}
}

func TestPublishRestoreAssetIntentDoesNotRequireUnrelatedRepositorySigningKey(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishMultiLeafPackageAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(input, []byte("asset-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	if err := os.WriteFile(input, []byte("asset-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "source_generation=1") || strings.Contains(stderr, "signing key") {
		t.Fatalf("asset-only restore with unrelated YUM config code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestPublishRestoreAssetIntentRejectsChangedParentRepositoryTrustAnchorBeforeMaterialization(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishMultiLeafPackageAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "package.rpm")
	if err := os.WriteFile(rpmPath, rpmBody, 0o444); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	assetPath := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(assetPath, []byte("asset-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"promote", "beta", "stable", "--config", configPath, "--repo", "rpm-test"},
		{"add", assetPath, "--config", configPath, "--repo", "assets", "--dest", "latest"},
		{"publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	}
	for _, args := range commands {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	if err := os.WriteFile(assetPath, []byte("asset-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", assetPath, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"},
		{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}

	rotatedKeyPath := writePublishTestPrivateKey(t, t.TempDir())
	for _, replacement := range []struct {
		source, target string
		mode           os.FileMode
	}{{rotatedKeyPath, keyPath, 0o600}, {rotatedKeyPath + ".pub", keyPath + ".pub", 0o644}} {
		body, err := os.ReadFile(replacement.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replacement.target, body, replacement.mode); err != nil {
			t.Fatal(err)
		}
	}
	putsBefore, purgesBefore, cdnBefore := transport.counts()
	code, stdout, stderr := run("publish", "--restore-generation", "2", "--target", "cf", "--config", configPath, "--workers", "2")
	putsAfter, purgesAfter, cdnAfter := transport.counts()
	if code != ExitConflict || !strings.Contains(stderr, "repository signing key changed") || !strings.Contains(stderr, "restore the recorded key") {
		t.Fatalf("changed parent trust anchor restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if putsAfter != putsBefore || purgesAfter != purgesBefore || cdnAfter != cdnBefore {
		t.Fatalf("rejected restore reached mutation/probe puts=%d/%d purges=%d/%d cdn=%d/%d", putsBefore, putsAfter, purgesBefore, purgesAfter, cdnBefore, cdnAfter)
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow", "materialized", "restores")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected restore created a materialization tree: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "state", "transactions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
		t.Fatalf("rejected restore retained transaction entries=%v err=%v", entries, err)
	}
}

func TestPublishRestoreStableAppendOnlyRegressionFailsBeforeRemoteMutation(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configuration := strings.Replace(publishAssetConfig, "default_pool: public", "default_pool: gated", 1)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for index, name := range []string{"one", "two"} {
		input := filepath.Join(root, name+".txt")
		if err := os.WriteFile(input, []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", name); code != ExitOK {
			t.Fatalf("stable add %d code=%d stdout=%s stderr=%s", index, code, stdout, stderr)
		}
		if code, stdout, stderr := run("publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
			t.Fatalf("stable publish %d code=%d stdout=%s stderr=%s", index, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	putsBefore, purgesBefore, cdnGetsBefore := transport.puts, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitConflict || !strings.Contains(stderr, "stable rollback is fail-closed") {
		t.Fatalf("append-only stable restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if transport.puts != putsBefore || transport.purges != purgesBefore || transport.cdnGets != cdnGetsBefore {
		t.Fatalf("rejected stable restore mutated remote puts=%d/%d purges=%d/%d cdn_gets=%d/%d", putsBefore, transport.puts, purgesBefore, transport.purges, cdnGetsBefore, transport.cdnGets)
	}
}

func TestPublishRestoreAssetPathRemovalUsesEvidenceBoundDeleteAndReplays(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for index, name := range []string{"one", "latest"} {
		input := filepath.Join(root, name+".txt")
		if err := os.WriteFile(input, []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", name); code != ExitOK {
			t.Fatalf("asset add %d code=%d stdout=%s stderr=%s", index, code, stdout, stderr)
		}
		if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
			t.Fatalf("asset publish %d code=%d stdout=%s stderr=%s", index, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	putsBefore, putOffset, deletesBefore, purgesBefore, cdnGetsBefore := transport.puts, len(transport.putKeys), transport.deletes, transport.purges, transport.cdnGets
	transport.cdnOverrides["https://beta.test/pkg/latest"] = protocolObject{body: []byte("stale cached asset")}
	transport.staleCDNOnPurge = true
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "still returns a successful response") {
		t.Fatalf("stale asset removal restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.deletes != deletesBefore+1 || transport.purges != purgesBefore+1 || transport.cdnGets <= cdnGetsBefore {
		transport.mutex.Unlock()
		t.Fatalf("failed restore closure puts=%d/%d deletes=%d/%d purges=%d/%d cdn_gets=%d/%d", putsBefore, transport.puts, deletesBefore, transport.deletes, purgesBefore, transport.purges, cdnGetsBefore, transport.cdnGets)
	}
	for _, key := range transport.putKeys[putOffset:] {
		if key == ".sow/beta/pkg/latest" {
			transport.mutex.Unlock()
			t.Fatalf("restore rewrote the object it planned to delete: puts=%v", transport.putKeys[putOffset:])
		}
	}
	if _, exists := transport.objects[".sow/beta/pkg/latest"]; exists {
		transport.mutex.Unlock()
		t.Fatal("failed negative CDN verification retained the exact origin object")
	}
	transport.staleCDNOnPurge = false
	transport.mutex.Unlock()

	code, stdout, stderr = run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("asset removal restore replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if transport.deletes != deletesBefore+1 || transport.purges <= purgesBefore+1 || transport.cdnGets <= cdnGetsBefore+1 {
		t.Fatalf("replayed restore closure puts=%d/%d deletes=%d/%d purges=%d/%d cdn_gets=%d/%d", putsBefore, transport.puts, deletesBefore, transport.deletes, purgesBefore, transport.purges, cdnGetsBefore, transport.cdnGets)
	}
	if _, exists := transport.objects[".sow/beta/pkg/latest"]; exists {
		t.Fatal("replayed restore retained removed beta asset")
	}
	latestSHA := publishDigest([]byte("latest\n"))
	if _, exists := transport.objects["objects/sha256/"+latestSHA]; !exists {
		t.Fatal("restore serving deletion removed the content-addressed asset archive")
	}
	if got := string(transport.objects[".sow/beta/pkg/one"].body); got != "one\n" {
		t.Fatalf("replayed restore changed retained historical asset=%q", got)
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	restorePlan, err := publish.DecodePlan(planBody)
	if err != nil || len(restorePlan.Deletes) != 1 {
		t.Fatalf("restore plan deletes=%#v err=%v", restorePlan.Deletes, err)
	}
	deletion := restorePlan.Deletes[0]
	if deletion.Class != publish.DeleteAssetServing || deletion.SourcePath != ".sow/materialized/beta/pkg/latest" || deletion.RemoteKey != ".sow/beta/pkg/latest" || deletion.CDNPath != "pkg/latest" || deletion.Size != 7 || deletion.SHA256 != latestSHA {
		t.Fatalf("restore deletion is not exact: %#v", deletion)
	}
}

func TestPublishRestoreLatestRemovesConfiguredExtraAssetLeaf(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	secondRepo := `  - id: assets-extra
    type: asset
    path: extra
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
`
	configText := strings.Replace(publishAssetConfig, "upstreams: []\n", secondRepo+"upstreams: []\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	addPromotePublish := func(repo, dest, body string) {
		t.Helper()
		input := filepath.Join(root, repo+".txt")
		if err := os.WriteFile(input, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, command := range [][]string{
			{"add", input, "--config", configPath, "--repo", repo, "--dest", dest},
			{"promote", "beta", "latest", "--config", configPath, "--repo", repo},
			{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", repo, "--workers", "2"},
		} {
			if code, stdout, stderr := run(command...); code != ExitOK {
				t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
			}
		}
	}
	addPromotePublish("assets", "one", "one\n")
	addPromotePublish("assets-extra", "two", "two\n")

	transport.mutex.Lock()
	deletesBefore, purgesBefore, getsBefore := transport.deletes, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("asset leaf restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.deletes != deletesBefore+1 || transport.purges != purgesBefore+1 || transport.cdnGets <= getsBefore {
		transport.mutex.Unlock()
		t.Fatalf("asset leaf delete closure deletes=%d/%d purges=%d/%d gets=%d/%d", deletesBefore, transport.deletes, purgesBefore, transport.purges, getsBefore, transport.cdnGets)
	}
	if _, exists := transport.objects["extra/two"]; exists {
		transport.mutex.Unlock()
		t.Fatal("historically absent configured asset leaf remained remotely served")
	}
	if got := string(transport.objects["pkg/one"].body); got != "one\n" {
		transport.mutex.Unlock()
		t.Fatalf("historical sibling asset changed=%q", got)
	}
	transport.mutex.Unlock()

	canonical := state.New(filepath.Join(root, ".sow"))
	generation, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || generation.Generation != 3 || generation.IntentView != "latest" || len(generation.Refs) != 1 || !strings.Contains(generation.Refs[0].Name, "/assets/") {
		t.Fatalf("restored asset leaf ref vector=%#v exists=%v err=%v", generation, exists, err)
	}
	if strings.Contains(generation.Refs[0].Name, "assets-extra") {
		t.Fatalf("removed asset leaf remains in active ref vector: %#v", generation.Refs)
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil || len(plan.Deletes) != 1 || plan.Deletes[0].SourcePath != "extra/two" || plan.Deletes[0].RemoteKey != "extra/two" || plan.Deletes[0].CDNPath != "extra/two" || plan.Deletes[0].SHA256 != publishDigest([]byte("two\n")) {
		t.Fatalf("asset leaf restore plan=%#v err=%v", plan, err)
	}
}

func TestResolveStablePublicationPoolsUsesHistoricalRestoreCommit(t *testing.T) {
	root := nginxWorkerTempDir(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("stable", "assets", "all", "all")
	viewRef, _ := state.ViewRef("stable", "assets", "all", "all")
	writeView := func(poolName string) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), "stable.tsv")
		var body bytes.Buffer
		if err := views.WriteEntry(&body, views.Entry{Repo: "assets", OS: "all", Arch: "all", Name: "secret", Version: "1", Path: "pkg/secret", Size: 1, SHA256: strings.Repeat("a", 64), Pool: poolName}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, body.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	historicalCommit, _, err := canonical.InstallPaths(map[string]string{viewPath: writeView("gated")}, "historical gated stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, historicalCommit, false); err != nil {
		t.Fatal(err)
	}
	currentCommit, _, err := canonical.InstallPaths(map[string]string{viewPath: writeView("public")}, "tampered current public stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(viewRef, historicalCommit, currentCommit, false); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", DefaultPool: "gated", Asset: &config.AssetConfig{Kind: "release"}}
	prepared := preparedPublication{
		view:         "stable",
		projections:  []publicationProjection{{view: "stable", repo: repo, os: "all", arch: "all", sourceRoot: ".sow/origin/gated/pkg", legacyRoot: "pkg"}},
		refOverrides: map[string]publish.RefState{viewRef.String(): {Name: viewRef.String(), Commit: historicalCommit.String(), ManifestSHA256: strings.Repeat("b", 64)}},
	}
	sourcePath := ".sow/origin/gated/pkg/secret"
	pools, err := resolveStablePublicationPools(canonical, &config.Config{}, prepared, []string{sourcePath})
	if err != nil || pools[sourcePath] != "gated" {
		t.Fatalf("historical stable pool=%q err=%v", pools[sourcePath], err)
	}
	classifier := publicationClassifier{view: "stable", generation: 3, projections: prepared.projections, stablePools: pools}
	remoteKey, class, err := classifier.classify(manifest.Entry{Path: sourcePath, Size: 1})
	if err != nil || class != publish.ObjectImmutable || remoteKey != ".sow/gated/pkg/secret" {
		t.Fatalf("historical gated route key=%q class=%s err=%v", remoteKey, class, err)
	}
}

func TestResolveStableAssetPoolUsesCanonicalRootWithRootPublicProjection(t *testing.T) {
	root := nginxWorkerTempDir(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("stable", "bootstrap", "all", "all")
	viewRef, _ := state.ViewRef("stable", "bootstrap", "all", "all")
	stage := filepath.Join(root, "stable-bootstrap.tsv")
	var body bytes.Buffer
	canonicalPath := "asset/bootstrap/pkg"
	if err := views.WriteEntry(&body, views.Entry{
		Repo: "bootstrap", OS: "all", Arch: "all", Name: "tool", Version: "1",
		Path: canonicalPath, Size: 1, SHA256: strings.Repeat("a", 64), Pool: "gated",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "stable bootstrap projection")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap", DefaultPool: "gated",
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: ".", RootKeys: []string{"pkg"}},
	}
	projection := publicationProjection{
		view: "stable", repo: repo, os: "all", arch: "all", sourceRoot: ".sow/origin/gated/asset/bootstrap",
		canonicalRoot: repo.Path, remoteRoot: repo.AssetPublicRoot(), legacyRoot: repo.Path,
	}
	prepared := preparedPublication{view: "stable", projections: []publicationProjection{projection}}
	sourcePath := ".sow/origin/gated/asset/bootstrap/pkg"
	pools, err := resolveStablePublicationPools(canonical, &config.Config{}, prepared, []string{sourcePath})
	if err != nil || pools[sourcePath] != "gated" {
		t.Fatalf("physical stable pool=%q err=%v", pools[sourcePath], err)
	}
	classifier := publicationClassifier{view: "stable", generation: 3, projections: prepared.projections, stablePools: pools}
	remoteKey, class, err := classifier.classify(manifest.Entry{Path: sourcePath, Size: 1})
	if err != nil || class != publish.ObjectImmutable || remoteKey != ".sow/gated/pkg" {
		t.Fatalf("root-projected stable route key=%q class=%s err=%v", remoteKey, class, err)
	}
}

func TestHistoricalAssetPublicationProjectionKeepsPhysicalAndPublicRoots(t *testing.T) {
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: "pkg"},
	}
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	for _, test := range []struct {
		name, view, snapshot, sourceRoot string
	}{
		{name: "latest", view: "latest", sourceRoot: "asset/bootstrap"},
		{name: "snapshot", view: "snapshot", snapshot: "stable-20260714", sourceRoot: ".sow/materialized/snapshots/stable-20260714/asset/bootstrap"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := preparedPublication{view: test.view, snapshotID: test.snapshot}
			projections, _, err := historicalPublicationProjections([]viewLeaf{leaf}, prepared, ".sow/materialized/restores/cf/1/"+test.view)
			if err != nil || len(projections) != 1 {
				t.Fatalf("projections=%#v err=%v", projections, err)
			}
			projection := projections[0]
			if projection.sourceRoot != test.sourceRoot || projection.canonicalPathRoot() != "asset/bootstrap" || projection.remotePathRoot() != "pkg" || !strings.HasSuffix(projection.localRoot, "/asset/bootstrap") {
				t.Fatalf("historical projection=%#v", projection)
			}
		})
	}
}

func TestHistoricalYUMPublicationProjectionGroupsLogicalAliases(t *testing.T) {
	repo := config.Repo{
		ID: "rpm", Type: "yum", Path: "yum/rpm/{arch}", Arches: []string{"x86_64"},
		OS:  config.OSConfig{Family: "el", Suite: "rocky", Major: 9, Lifecycle: "active"},
		YUM: &config.YUMConfig{Compression: "zstd"},
	}
	leaves := []viewLeaf{
		{repo: repo, os: "rocky", arch: "x86_64"},
		{repo: repo, os: "el9", arch: "x86_64"},
	}
	prepared := preparedPublication{view: "latest"}
	projections, owners, err := historicalPublicationProjections(leaves, prepared, ".sow/materialized/restores/cf/1/latest")
	if err != nil || len(projections) != 1 {
		t.Fatalf("grouped historical projections=%#v owners=%#v err=%v", projections, owners, err)
	}
	key := yumPublicationOwnerKey(repo.ID, "x86_64")
	prepared.projections, prepared.yumOwnerLeaves = projections, owners
	if len(owners[key]) != 2 || prepared.validateYUMOwnerVectors() != nil {
		t.Fatalf("historical YUM alias vector=%#v", owners)
	}
	variants := prepared.yumChannelProjections(projections[0])
	if len(variants) != 2 || variants[0].os != "el9" || variants[1].os != "rocky" {
		t.Fatalf("historical YUM channel variants=%#v", variants)
	}
}

func TestResolveStablePublicationPoolsAllowsPartialHistoricalAPTIntent(t *testing.T) {
	root := nginxWorkerTempDir(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("stable", "deb", "jammy", "amd64")
	viewRef, _ := state.ViewRef("stable", "deb", "jammy", "amd64")
	stage := filepath.Join(t.TempDir(), "stable-amd64.tsv")
	var body bytes.Buffer
	entryPath := "apt/test/pool/main/p/pkg.deb"
	if err := views.WriteEntry(&body, views.Entry{Repo: "deb", OS: "jammy", Arch: "amd64", Name: "pkg", Version: "1", Path: entryPath, Size: 1, SHA256: strings.Repeat("a", 64), Pool: "gated"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	historicalCommit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "partial historical APT stable")
	if err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{
		ID: "deb", Type: "apt", Path: "apt/test", DefaultPool: "gated", Arches: []string{"amd64", "arm64"},
		APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}},
	}
	prepared := preparedPublication{
		view:         "stable",
		projections:  []publicationProjection{{view: "stable", repo: repo, sourceRoot: ".sow/origin/gated/apt/test", legacyRoot: "apt/test"}},
		refOverrides: map[string]publish.RefState{viewRef.String(): {Name: viewRef.String(), Commit: historicalCommit.String(), ManifestSHA256: strings.Repeat("b", 64)}},
	}
	sourcePath := ".sow/origin/gated/" + entryPath
	pools, err := resolveStablePublicationPools(canonical, &config.Config{}, prepared, []string{sourcePath})
	if err != nil || pools[sourcePath] != "gated" {
		t.Fatalf("partial historical APT pool=%q err=%v", pools[sourcePath], err)
	}
}

func TestPublishRestoreGenerationPreservesOtherIntentVector(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", fixture.configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", fixture.configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("publish latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	before, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || before.Generation != 3 || before.IntentView != "latest" {
		t.Fatalf("pre-restore generation=%#v exists=%v err=%v", before, exists, err)
	}
	latestRefName, _ := state.ViewRef("latest", "assets", "all", "all")
	var latestBefore publish.RefState
	for _, ref := range before.Refs {
		if ref.Name == latestRefName.String() {
			latestBefore = ref
		}
	}
	if latestBefore.Name == "" {
		t.Fatal("latest generation omitted latest ref")
	}
	if code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("restore beta with latest present code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || after.Generation != 4 || after.ParentGeneration != 3 || after.IntentView != "beta" {
		t.Fatalf("post-restore generation=%#v exists=%v err=%v", after, exists, err)
	}
	refs := make(map[string]publish.RefState, len(after.Refs))
	for _, ref := range after.Refs {
		refs[ref.Name] = ref
	}
	if got := refs[fixture.sourceRef.Name].Commit; got != fixture.sourceRef.Commit {
		t.Fatalf("restored beta ref=%s want=%s", got, fixture.sourceRef.Commit)
	}
	if got := refs[latestBefore.Name]; got != latestBefore {
		t.Fatalf("latest ref changed during beta restore got=%#v want=%#v", got, latestBefore)
	}
	latestRemoteRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	latestRemoteCommit, exists, err := fixture.canonical.Ref(latestRemoteRef)
	if err != nil || !exists || latestRemoteCommit.String() != latestBefore.Commit {
		t.Fatalf("latest remote ref=%s want=%s exists=%v err=%v", latestRemoteCommit, latestBefore.Commit, exists, err)
	}
	fixture.transport.mutex.Lock()
	defer fixture.transport.mutex.Unlock()
	if got := string(fixture.transport.objects["pkg/latest"].body); got != "restore-fixture-two\n" {
		t.Fatalf("latest serving intent changed during beta restore=%q", got)
	}
	if got := string(fixture.transport.objects[".sow/beta/pkg/latest"].body); got != "restore-fixture-one\n" {
		t.Fatalf("beta serving intent was not restored=%q", got)
	}
}

func TestPublishAfterRestoreAdvancesCurrentDesiredWithoutCheckpointRewind(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", fixture.configPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", fixture.configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "generation=4") || !strings.Contains(stdout, "status=published") {
		t.Fatalf("forward publish after restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	current, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || current.Generation != 4 || current.ParentGeneration != 3 || current.IntentView != "beta" {
		t.Fatalf("forward generation=%#v exists=%v err=%v", current, exists, err)
	}
	remoteRef, _ := state.RemoteRef("cf", "beta", "assets", "all", "all")
	remoteCommit, exists, err := fixture.canonical.Ref(remoteRef)
	localRef, _ := state.ViewRef("beta", "assets", "all", "all")
	localCommit, localExists, localErr := fixture.canonical.Ref(localRef)
	if err != nil || localErr != nil || !exists || !localExists || remoteCommit != localCommit {
		t.Fatalf("forward refs remote=%s local=%s remote_exists=%v local_exists=%v errors=%v/%v", remoteCommit, localCommit, exists, localExists, err, localErr)
	}
	fixture.transport.mutex.Lock()
	defer fixture.transport.mutex.Unlock()
	if got := string(fixture.transport.objects[".sow/beta/pkg/latest"].body); got != "restore-fixture-two\n" {
		t.Fatalf("forward publish did not restore current desired body=%q", got)
	}
	checkpoint, err := publish.DecodeCheckpoint(fixture.transport.objects[publish.CheckpointKey].body)
	if err != nil || checkpoint.Generation != 4 || checkpoint.ParentGeneration != 3 {
		t.Fatalf("forward checkpoint=%#v err=%v", checkpoint, err)
	}
}

func TestPublishRestoreRefOnlyCarriesCDNProbeAcrossOtherIntentHistory(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousPublishClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousPublishClient
		verificationHTTPClient = previousVerificationClient
	})
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	asset := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(asset, []byte("ref-only-stable-bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", asset, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("seed beta publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	betaRef, _ := state.ViewRef("beta", "assets", "all", "all")
	betaOne, exists, err := canonical.Ref(betaRef)
	if err != nil || !exists {
		t.Fatalf("seed beta ref=%s exists=%v err=%v", betaOne, exists, err)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	sameBytesCommit, err := canonical.HeadHash()
	if err != nil || sameBytesCommit == betaOne {
		t.Fatalf("same-byte aggregate commit=%s beta=%s err=%v", sameBytesCommit, betaOne, err)
	}
	if err := canonical.AdvanceRef(betaRef, betaOne, sameBytesCommit, false); err != nil {
		t.Fatal(err)
	}

	transport.mutex.Lock()
	putOffset, getOffset := len(transport.putKeys), len(transport.cdnURLs)
	transport.mutex.Unlock()
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "generation=2") {
		t.Fatalf("ref-only beta publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	refOnlyPuts := append([]string(nil), transport.putKeys[putOffset:]...)
	refOnlyGets := append([]string(nil), transport.cdnURLs[getOffset:]...)
	transport.mutex.Unlock()
	for _, key := range refOnlyPuts {
		if key == ".sow/beta/pkg/latest" || key == "pkg/latest" {
			t.Fatalf("ref-only generation re-uploaded unchanged asset: puts=%v", refOnlyPuts)
		}
	}
	if len(refOnlyGets) == 0 {
		t.Fatal("ref-only generation did not revalidate a carried CDN probe")
	}

	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "generation=3") {
		t.Fatalf("other-intent publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	putOffset, getOffset = len(transport.putKeys), len(transport.cdnURLs)
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "generation=4") || !strings.Contains(stdout, "source_generation=1") {
		t.Fatalf("ref-only restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	restorePuts := append([]string(nil), transport.putKeys[putOffset:]...)
	restoreGets := append([]string(nil), transport.cdnURLs[getOffset:]...)
	transport.mutex.Unlock()
	for _, key := range restorePuts {
		if key == ".sow/beta/pkg/latest" || key == "pkg/latest" {
			t.Fatalf("ref-only restore re-uploaded unchanged asset: puts=%v", restorePuts)
		}
	}
	if len(restoreGets) == 0 {
		t.Fatal("ref-only restore did not revalidate a carried CDN probe")
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "intents", "views", "beta", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil || len(plan.Objects) != 0 || len(plan.Probes) != 1 || len(plan.VerifyAbsent) != 0 {
		t.Fatalf("ref-only restore plan=%#v err=%v", plan, err)
	}
	if code, stdout, stderr := run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") || strings.Contains(stdout, "CDN_PROBE_UNCONFIGURED") {
		t.Fatalf("ref-only restore L3 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestLoadHistoricalTargetPublicationRequiresCheckpointPlanAndContentEvidence(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	historical, err := loadHistoricalTargetPublication(fixture.canonical, "cf", 1)
	if err != nil {
		t.Fatal(err)
	}
	generationBody, exists, err := readCanonicalBytesAt(fixture.canonical, historical.StateCommit, remoteStatePath("cf", "generation.json"), 16<<20)
	if err != nil || !exists {
		t.Fatalf("read generation evidence exists=%v err=%v", exists, err)
	}
	checkpointBody, exists, err := readCanonicalBytesAt(fixture.canonical, historical.StateCommit, remoteStatePath("cf", "checkpoint.json"), 16<<20)
	if err != nil || !exists {
		t.Fatalf("read checkpoint evidence exists=%v err=%v", exists, err)
	}
	planBody, exists, err := readCanonicalBytesAt(fixture.canonical, historical.StateCommit, remoteStatePath("cf", "plan.json"), 64<<20)
	if err != nil || !exists {
		t.Fatalf("read plan evidence exists=%v err=%v", exists, err)
	}
	checkpoint, err := publish.DecodeCheckpoint(checkpointBody)
	if err != nil {
		t.Fatal(err)
	}
	validCheckpoint := checkpoint
	checkpoint.DesiredCommit = strings.Repeat("1", 40)
	invalidCheckpointBody, err := checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	unrelatedPlan := publish.Plan{}
	unrelatedPlanBody, err := unrelatedPlan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	unrelatedPlanSHA, err := unrelatedPlan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCheckpoint := validCheckpoint
	unrelatedCheckpoint.PlanSHA256 = unrelatedPlanSHA
	unrelatedCheckpointBody, err := unrelatedCheckpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	intentGenerationPath, _ := remoteIntentStatePath("cf", historical.Generation.IntentView, historical.Generation.IntentSnapshot, "generation.json")
	intentCheckpointPath, _ := remoteIntentStatePath("cf", historical.Generation.IntentView, historical.Generation.IntentSnapshot, "checkpoint.json")
	intentPlanPath, _ := remoteIntentStatePath("cf", historical.Generation.IntentView, historical.Generation.IntentSnapshot, "plan.json")
	globalGenerationPath := remoteStatePath("cf", "generation.json")
	globalCheckpointPath := remoteStatePath("cf", "checkpoint.json")
	globalPlanPath := remoteStatePath("cf", "plan.json")
	for _, test := range []struct {
		name     string
		contents map[string][]byte
		want     string
	}{
		{name: "checkpoint", contents: map[string][]byte{globalGenerationPath: generationBody}, want: "checkpoint is missing"},
		{name: "checkpoint-closure", contents: map[string][]byte{globalGenerationPath: generationBody, globalCheckpointPath: invalidCheckpointBody}, want: "generation/checkpoint closure is invalid"},
		{name: "plan", contents: map[string][]byte{globalGenerationPath: generationBody, globalCheckpointPath: checkpointBody}, want: "publication plan is missing"},
		{name: "plan-intent-binding", contents: map[string][]byte{
			globalGenerationPath: generationBody, globalCheckpointPath: unrelatedCheckpointBody, globalPlanPath: unrelatedPlanBody,
			intentGenerationPath: generationBody, intentCheckpointPath: unrelatedCheckpointBody, intentPlanPath: planBody,
		}, want: "intent beta evidence is missing or differs from target-global plan.json"},
		{name: "content", contents: map[string][]byte{
			globalGenerationPath: generationBody, globalCheckpointPath: checkpointBody, globalPlanPath: planBody,
			intentGenerationPath: generationBody, intentCheckpointPath: checkpointBody, intentPlanPath: planBody,
		}, want: "historical content manifest digest="},
	} {
		t.Run(test.name, func(t *testing.T) {
			canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
			staged := make(map[string]string, len(test.contents))
			index := 0
			for canonicalPath, body := range test.contents {
				file := filepath.Join(t.TempDir(), fmt.Sprintf("evidence-%d", index))
				index++
				if err := os.WriteFile(file, body, 0o600); err != nil {
					t.Fatal(err)
				}
				staged[canonicalPath] = file
			}
			if _, _, err := canonical.InstallPaths(staged, "incomplete historical publication evidence"); err != nil {
				t.Fatal(err)
			}
			if _, err := loadHistoricalTargetPublication(canonical, "cf", 1); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("incomplete evidence err=%v want=%q", err, test.want)
			}
		})
	}
}

func TestPrepareHistoricalPublicationFailsClosedOnMissingRefAndTopologyRemoval(t *testing.T) {
	fixture := newAssetRestoreFixture(t)
	historical, err := loadHistoricalTargetPublication(fixture.canonical, "cf", 1)
	if err != nil {
		t.Fatal(err)
	}
	parent, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || parent.Generation != 2 {
		t.Fatalf("parent=%#v exists=%v err=%v", parent, exists, err)
	}
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	t.Run("missing-ref-commit", func(t *testing.T) {
		candidate := historical
		candidate.Generation.Refs = append([]publish.RefState(nil), historical.Generation.Refs...)
		candidate.Generation.Refs[0].Commit = strings.Repeat("1", 40)
		_, err := prepareHistoricalPublication(t.Context(), fixture.cfg, fixture.cfg, fixture.canonical, pool, fixture.cfg.Repos, "cf", candidate, &parent, t.TempDir(), values, nil, nil, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "outside canonical HEAD history") {
			t.Fatalf("missing historical ref err=%v", err)
		}
	})
	t.Run("topology-removal", func(t *testing.T) {
		candidateParent := parent
		candidateParent.Refs = append([]publish.RefState(nil), parent.Refs...)
		candidateParent.Refs = append(candidateParent.Refs, publish.RefState{
			Name: "refs/sow/views/beta/removed-repository/all/all", Commit: fixture.sourceRef.Commit,
		})
		_, err := prepareHistoricalPublication(t.Context(), fixture.cfg, fixture.cfg, fixture.canonical, pool, fixture.cfg.Repos, "cf", historical, &candidateParent, t.TempDir(), values, nil, nil, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "topology-removal restore is fail-closed") {
			t.Fatalf("topology-removal err=%v", err)
		}
	})
	t.Run("configured-package-topology-removal", func(t *testing.T) {
		candidateCfg := *fixture.cfg
		candidateCfg.Repos = append(append([]config.Repo(nil), fixture.cfg.Repos...), config.Repo{
			ID: "rpm-extra", Type: "yum", Path: "yum/extra", DefaultPool: "public",
			OS: config.OSConfig{Family: "el", Major: 10, Lifecycle: "active"}, Arches: []string{"x86_64"},
			YUM: &config.YUMConfig{Compression: "zstd"},
		})
		extraRef, err := state.ViewRef("beta", "rpm-extra", "el10", "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		candidateParent := parent
		candidateParent.Refs = append(append([]publish.RefState(nil), parent.Refs...), publish.RefState{
			Name: extraRef.String(), Commit: fixture.sourceRef.Commit, ManifestSHA256: fixture.sourceRef.ManifestSHA256,
		})
		candidateParent.Channels = append(candidateParent.Channels, publish.ChannelState{
			View: "beta", Repo: "rpm-extra", OS: "el10", Arch: "x86_64", Generation: candidateParent.Generation,
			RemoteKey: ".sow/channels/beta/rpm-extra/el10/x86_64.json", LegacyRoot: "yum/extra",
		})
		canonicalConfig, err := candidateCfg.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		configStage := filepath.Join(t.TempDir(), "parent-config.yaml")
		if err := os.WriteFile(configStage, canonicalConfig, 0o600); err != nil {
			t.Fatal(err)
		}
		parentCommit, _, err := fixture.canonical.InstallPaths(map[string]string{"config/sow.yaml": configStage}, "parent config includes removable YUM topology")
		if err != nil {
			t.Fatal(err)
		}
		candidateParent.DesiredCommit = parentCommit.String()
		prepared, err := prepareHistoricalPublication(t.Context(), &candidateCfg, &candidateCfg, fixture.canonical, pool, candidateCfg.Repos, "cf", historical, &candidateParent, t.TempDir(), values, nil, nil, io.Discard)
		if err != nil {
			t.Fatalf("configured package topology-removal err=%v", err)
		}
		if !prepared.restoreRemovedProjectionRoots[".sow/materialized/beta/yum/extra"] || !prepared.restoreRemovedChannelKeys[".sow/channels/beta/rpm-extra/el10/x86_64.json"] {
			t.Fatalf("configured package topology-removal authority was not frozen: roots=%v channels=%v", prepared.restoreRemovedProjectionRoots, prepared.restoreRemovedChannelKeys)
		}
	})
}

func TestRemovedYUMChannelDeletionRejectsPartialPublicationClosure(t *testing.T) {
	root := nginxWorkerTempDir(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	viewBody := []byte("view\n")
	viewStage := filepath.Join(root, "view.tsv")
	configStage := filepath.Join(root, "parent-config.yaml")
	if err := os.WriteFile(viewStage, viewBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configStage, []byte("parent-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	desiredCommit, _, err := canonical.InstallPaths(map[string]string{
		"views/latest/rpm/el10/x86_64.tsv": viewStage,
		"config/sow.yaml":                  configStage,
	}, "seed parent desired state")
	if err != nil {
		t.Fatal(err)
	}
	channel := publish.ChannelState{
		View: "latest", Repo: "rpm", OS: "el10", Arch: "x86_64", Generation: 1,
		RemoteKey: ".sow/channels/latest/rpm/el10/x86_64.json", LegacyRoot: "yum/rpm/x86_64",
	}
	channelBody, err := channel.CanonicalBody()
	if err != nil {
		t.Fatal(err)
	}
	channel.BodySHA256 = digestBytesCLI(channelBody)
	mirrorKey := "_sow/v1/mirrorlist/latest/rpm/el10/x86_64.txt"
	mirrorBody := []byte("https://parent-generation.example/_sow/v1/g/00000000000000000001/yum/rpm/x86_64/\n")
	plan, err := (publish.Plan{Objects: []publish.PlannedObject{{
		SourcePath: ".sow/generated/mirrorlists/cf/latest/rpm/el10/x86_64.txt",
		RemoteKey:  mirrorKey, Size: int64(len(mirrorBody)), SHA256: digestBytesCLI(mirrorBody),
		Class: publish.ObjectPointer, CDNPath: mirrorKey,
	}}}).WithCDN("https://parent-generation.example/")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, err := state.ViewRef("latest", "rpm", "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	generation := publish.TargetGeneration{
		Schema: publish.TargetGenerationSchema, Target: publish.TargetCloudflare,
		Generation: 1, ParentGeneration: 0, DesiredCommit: desiredCommit.String(), IntentView: "latest",
		ConfigSHA256: strings.Repeat("a", 64), ContentManifestSHA256: strings.Repeat("b", 64),
		Refs:     []publish.RefState{{Name: viewRef.String(), Commit: desiredCommit.String(), ManifestSHA256: digestBytesCLI(viewBody)}},
		Channels: []publish.ChannelState{channel},
	}
	generationBody, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	generationStage, planStage := filepath.Join(root, "generation.json"), filepath.Join(root, "plan.json")
	if err := os.WriteFile(generationStage, generationBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planStage, planBody, 0o600); err != nil {
		t.Fatal(err)
	}
	publicationCommit, _, err := canonical.InstallPaths(map[string]string{
		remoteStatePath("cf", "generation.json"): generationStage,
		remoteStatePath("cf", "plan.json"):       planStage,
	}, "persist parent publication")
	if err != nil {
		t.Fatal(err)
	}
	laterConfig := filepath.Join(root, "later-config.yaml")
	if err := os.WriteFile(laterConfig, []byte("later-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": laterConfig}, "later unrelated state"); err != nil {
		t.Fatal(err)
	}
	foundCommit, _, err := targetGenerationPublicationState(canonical, "cf", 1)
	if err != nil || foundCommit != publicationCommit {
		t.Fatalf("publication state commit=%s want=%s err=%v", foundCommit, publicationCommit, err)
	}

	prepared := preparedPublication{
		view: "latest", restoreSourceGeneration: 1,
		restoreRemovedChannelKeys: map[string]bool{channel.RemoteKey: true},
	}
	var restorePlan publish.Plan
	if err := augmentRemovedYUMChannelDeletes(canonical, "cf", prepared, &generation, nil, &restorePlan); err == nil || !strings.Contains(err.Error(), "complete successful-publication closure") {
		t.Fatalf("partial generation+plan history authorized deletion: plan=%#v err=%v", restorePlan, err)
	}

	missingChannel := generation
	missingChannel.Channels = nil
	if err := augmentRemovedYUMChannelDeletes(canonical, "cf", prepared, &missingChannel, nil, &publish.Plan{}); err == nil || !strings.Contains(err.Error(), "no exact parent channel state") {
		t.Fatalf("missing parent channel state was accepted: %v", err)
	}
}

func TestPublishRestoreGenerationRebuildsSignedAPTAndYUMIntent(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishRestorePackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	writeVerifyPublicKey(t, keyPath)
	debOne := writeRetentionDEB(t, root, "1.0.0")
	debTwo := writeRetentionDEB(t, root, "2.0.0")
	rpmOne := writeRestoreRPMFixture(t, root, "1.0.0")
	rpmTwo := writeRestoreRPMFixture(t, root, "2.0.0")
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, artifact := range []struct{ path, repo string }{{debOne, "deb-restore"}, {rpmOne, "rpm-restore"}} {
		if code, stdout, stderr := run("add", artifact.path, "--config", configPath, "--repo", artifact.repo, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
			t.Fatalf("seed add %s code=%d stdout=%s stderr=%s", artifact.repo, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("seed package publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, artifact := range []struct{ path, repo string }{{debTwo, "deb-restore"}, {rpmTwo, "rpm-restore"}} {
		if code, stdout, stderr := run("add", artifact.path, "--config", configPath, "--repo", artifact.repo, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
			t.Fatalf("second add %s code=%d stdout=%s stderr=%s", artifact.repo, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("second package publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	putOffset, purgeOffset, getOffset, deletesBeforeRestore := len(transport.putKeys), len(transport.purgeURLs), len(transport.cdnURLs), transport.deletes
	transport.mutex.Unlock()

	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "source_generation=1") || !strings.Contains(stdout, "apt_suites=1") || !strings.Contains(stdout, "yum_repos=1") {
		t.Fatalf("package restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	objects := make(map[string]protocolObject, len(transport.objects))
	for key, value := range transport.objects {
		objects[key] = value
	}
	putKeys := append([]string(nil), transport.putKeys[putOffset:]...)
	purgeURLs := append([]string(nil), transport.purgeURLs[purgeOffset:]...)
	cdnURLs := append([]string(nil), transport.cdnURLs[getOffset:]...)
	deletesAfterRestore := transport.deletes
	transport.mutex.Unlock()
	if deletesAfterRestore <= deletesBeforeRestore {
		t.Fatalf("package restore did not retire obsolete serving-index metadata before=%d after=%d", deletesBeforeRestore, deletesAfterRestore)
	}
	aptPayloads, yumPayloads, generationTwoMetadata := 0, 0, 0
	for key := range objects {
		switch {
		case strings.HasPrefix(key, "apt/restore/pool/") && strings.HasSuffix(key, ".deb"):
			aptPayloads++
		case strings.HasPrefix(key, "yum/restore/x86_64/Packages/") && strings.HasSuffix(key, ".rpm"):
			yumPayloads++
		case strings.HasPrefix(key, ".sow/generations/00000000000000000002/"):
			generationTwoMetadata++
		}
	}
	if aptPayloads < 2 || yumPayloads < 2 || generationTwoMetadata == 0 {
		t.Fatalf("restore removed preservation roots apt_payloads=%d yum_payloads=%d generation2_metadata=%d", aptPayloads, yumPayloads, generationTwoMetadata)
	}
	restorePlanBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	restorePlan, err := publish.DecodePlan(restorePlanBody)
	if err != nil || len(restorePlan.Deletes) != deletesAfterRestore-deletesBeforeRestore {
		t.Fatalf("restore delete plan=%#v err=%v", restorePlan.Deletes, err)
	}
	for _, deletion := range restorePlan.Deletes {
		if deletion.Class != publish.DeleteRestoreIndexServing || strings.Contains(deletion.CDNPath, "/pool/") || strings.Contains(deletion.CDNPath, "/Packages/") {
			t.Fatalf("restore deleted a non-index preservation root: %#v", deletion)
		}
	}

	checkpoint, err := publish.DecodeCheckpoint(objects[publish.CheckpointKey].body)
	if err != nil || checkpoint.Generation != 3 || checkpoint.ParentGeneration != 2 || checkpoint.IntentView != "beta" {
		t.Fatalf("restore checkpoint=%#v err=%v", checkpoint, err)
	}
	generationKey, _ := publish.GenerationKey(3)
	restoredGeneration, err := publish.DecodeTargetGeneration(objects[generationKey].body)
	if err != nil || len(restoredGeneration.Refs) != 2 || len(restoredGeneration.Channels) != 1 || restoredGeneration.ContentManifestSHA256 != checkpoint.ContentManifestSHA256 {
		t.Fatalf("restore generation=%#v err=%v", restoredGeneration, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	contentDigest, exists, err := hashCanonicalPathOptionalAt(canonical, mustHeadHash(t, canonical), remoteStatePath("cf", "content.tsv"))
	if err != nil || !exists || contentDigest != restoredGeneration.ContentManifestSHA256 {
		t.Fatalf("restore L2 content digest=%s want=%s exists=%v err=%v", contentDigest, restoredGeneration.ContentManifestSHA256, exists, err)
	}

	aptRoot := ".sow/beta/apt/restore/dists/jammy"
	release := objects[aptRoot+"/Release"].body
	inRelease := objects[aptRoot+"/InRelease"].body
	detached := objects[aptRoot+"/Release.gpg"].body
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	aptSigner, err := aptrepo.NewSigner(bytes.NewReader(privateKey), nil)
	if err != nil || aptSigner.Verify(release, inRelease, detached, time.Now().UTC()) != nil {
		t.Fatalf("restored APT signature verification err=%v", err)
	}
	packagesObject, exists := objects[aptRoot+"/main/binary-amd64/Packages.gz"]
	if !exists {
		t.Fatal("restored APT Packages.gz is missing")
	}
	gz, err := gzip.NewReader(bytes.NewReader(packagesObject.body))
	if err != nil {
		t.Fatal(err)
	}
	packages, err := io.ReadAll(gz)
	if closeErr := gz.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if !bytes.Contains(packages, []byte("Version: 1.0.0\n")) || bytes.Contains(packages, []byte("Version: 2.0.0\n")) {
		t.Fatalf("restored APT package set=%s", packages)
	}

	yumGenerationPrefix := ".sow/generations/00000000000000000003/yum/yum/restore/x86_64/repodata/"
	repodataDir := filepath.Join(t.TempDir(), "repodata")
	if err := os.MkdirAll(repodataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for key, value := range objects {
		if strings.HasPrefix(key, yumGenerationPrefix) {
			if err := os.WriteFile(filepath.Join(repodataDir, strings.TrimPrefix(key, yumGenerationPrefix)), value.body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	yumGeneration, err := yumrepo.ValidateDirectory(t.Context(), repodataDir, yumrepo.CompressionZstd, verifier)
	if err != nil || yumGeneration.Packages != 1 {
		t.Fatalf("restored YUM metadata packages=%d err=%v", yumGeneration.Packages, err)
	}
	aliasRoot := ".sow/beta/yum/restore/x86_64/repodata/"
	if !bytes.Equal(objects[aliasRoot+"repomd.xml"].body, objects[yumGenerationPrefix+"repomd.xml"].body) || !bytes.Equal(objects[aliasRoot+"repomd.xml.asc"].body, objects[yumGenerationPrefix+"repomd.xml.asc"].body) {
		t.Fatal("restored YUM raw signature pair differs from generation 3")
	}
	channel, err := publish.DecodeTargetGeneration(objects[generationKey].body)
	if err != nil || channel.Channels[0].Generation != 3 {
		t.Fatalf("restored YUM channel=%#v err=%v", channel.Channels, err)
	}

	joinedPurge := strings.Join(purgeURLs, "\n")
	for _, required := range []string{
		"https://beta.test/apt/restore/dists/jammy/InRelease",
		"https://beta.test/yum/restore/x86_64/repodata/repomd.xml",
		"https://beta.test/yum/restore/x86_64/repodata/repomd.xml.asc",
		"https://beta.test/_sow/v1/mirrorlist/beta/rpm-restore/el10/x86_64.txt",
	} {
		if !strings.Contains(joinedPurge, required) {
			t.Fatalf("restore minimal purge omitted %s: %v", required, purgeURLs)
		}
	}
	if len(cdnURLs) == 0 || len(putKeys) == 0 {
		t.Fatalf("restore did not exercise remote L3/PUT closure puts=%v cdn=%v", putKeys, cdnURLs)
	}
	transport.mutex.Lock()
	putsAfter, purgesAfter, getsAfter := transport.puts, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr = run("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("signed package restore replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if transport.puts != putsAfter || transport.purges != purgesAfter || transport.cdnGets != getsAfter {
		t.Fatalf("signed package restore replay repeated remote effects puts=%d/%d purges=%d/%d gets=%d/%d", putsAfter, transport.puts, purgesAfter, transport.purges, getsAfter, transport.cdnGets)
	}
}

func TestPublishRestoreRemovesAPTAndYUMTopologyTransactionally(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishTopologyRestoreConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	writeVerifyPublicKey(t, keyPath)
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousClient
		verificationHTTPClient = previousVerificationClient
	})
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	runOK := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := run(args...)
		if code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
		return stdout
	}

	asset := filepath.Join(root, "anchor.txt")
	if err := os.WriteFile(asset, []byte("anchor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runOK("add", asset, "--config", configPath, "--repo", "assets", "--dest", "anchor")
	runOK("promote", "beta", "latest", "--config", configPath, "--repo", "assets")
	runOK("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")

	deb := writeRetentionDEB(t, root, "3.0.0")
	rpm := writeRestoreRPMFixture(t, root, "3.0.0")
	for _, artifact := range []struct{ path, repo string }{{deb, "deb-topology"}, {rpm, "rpm-topology"}} {
		runOK("add", artifact.path, "--config", configPath, "--repo", artifact.repo, "--gpg-private-key-file", keyPath, "--workers", "2")
		runOK("promote", "beta", "latest", "--config", configPath, "--repo", artifact.repo)
	}
	runOK("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "deb-topology", "--repo", "rpm-topology", "--gpg-private-key-file", keyPath, "--workers", "2")

	stdout := runOK("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if !strings.Contains(stdout, "source_generation=1") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("topology restore output=%s", stdout)
	}

	transport.mutex.Lock()
	objects := make(map[string]protocolObject, len(transport.objects))
	for key, value := range transport.objects {
		objects[key] = value
	}
	transport.mutex.Unlock()
	aptPayload, yumPayload, immutableAPT, immutableYUM := false, false, false, false
	for key := range objects {
		switch {
		case strings.HasPrefix(key, "apt/topology/pool/") && strings.HasSuffix(key, ".deb"):
			aptPayload = true
		case strings.HasPrefix(key, "yum/topology/x86_64/Packages/") && strings.HasSuffix(key, ".rpm"):
			yumPayload = true
		case strings.HasPrefix(key, ".sow/generations/00000000000000000002/apt/"):
			immutableAPT = true
		case strings.HasPrefix(key, ".sow/generations/00000000000000000002/yum/"):
			immutableYUM = true
		}
		if strings.HasPrefix(key, "apt/topology/dists/") || strings.HasPrefix(key, "yum/topology/x86_64/repodata/") || key == "_sow/v1/mirrorlist/latest/rpm-topology/el10/x86_64.txt" {
			t.Fatalf("removed topology entry point remains remotely served: %s", key)
		}
	}
	if !aptPayload || !yumPayload || !immutableAPT || !immutableYUM {
		t.Fatalf("topology restore lost preservation roots apt_payload=%t yum_payload=%t immutable_apt=%t immutable_yum=%t", aptPayload, yumPayload, immutableAPT, immutableYUM)
	}

	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil || len(plan.Deletes) == 0 || len(plan.VerifyAbsent) != len(plan.Deletes) || len(plan.PurgeURLs) != len(plan.Deletes) {
		t.Fatalf("topology restore plan deletes=%d absent=%d purges=%d err=%v", len(plan.Deletes), len(plan.VerifyAbsent), len(plan.PurgeURLs), err)
	}
	aptDelete, yumDelete, mirrorDelete := false, false, false
	for _, deletion := range plan.Deletes {
		if deletion.Class != publish.DeleteRestoreIndexServing || strings.Contains(deletion.RemoteKey, "/pool/") || strings.Contains(deletion.RemoteKey, "/Packages/") {
			t.Fatalf("unsafe topology deletion=%#v", deletion)
		}
		aptDelete = aptDelete || strings.Contains(deletion.RemoteKey, "apt/topology/dists/")
		yumDelete = yumDelete || strings.Contains(deletion.RemoteKey, "yum/topology/x86_64/repodata/")
		mirrorDelete = mirrorDelete || deletion.RemoteKey == "_sow/v1/mirrorlist/latest/rpm-topology/el10/x86_64.txt"
	}
	if !aptDelete || !yumDelete || !mirrorDelete {
		t.Fatalf("topology deletion classes incomplete apt=%t yum=%t mirror=%t deletes=%#v", aptDelete, yumDelete, mirrorDelete, plan.Deletes)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	generation, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || generation.Generation != 3 || len(generation.Refs) != 1 || len(generation.Channels) != 0 || !strings.Contains(generation.Refs[0].Name, "/assets/") {
		t.Fatalf("restored topology generation=%#v exists=%v err=%v", generation, exists, err)
	}
	refs, err := canonical.SOWRefs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if strings.HasPrefix(ref.Name.String(), "refs/sow/remotes/cf/latest/deb-topology/") || strings.HasPrefix(ref.Name.String(), "refs/sow/remotes/cf/latest/rpm-topology/") {
			t.Fatalf("removed remote topology ref remains: %s", ref.Name)
		}
	}
	staleChannelPath := remoteStatePath("cf", filepath.ToSlash(filepath.Join("channels", "latest", "rpm-topology", "el10", "x86_64.json")))
	if _, exists, err := readOptionalCanonical(canonical, staleChannelPath); err != nil || exists {
		t.Fatalf("removed canonical channel state remains path=%s exists=%v err=%v", staleChannelPath, exists, err)
	}
	if code, verifyOut, verifyErr := run("verify", "--layer", "L3", "--view", "latest", "--target", "cf", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(verifyOut, "outcome=passed") {
		t.Fatalf("restored topology L3 code=%d stdout=%s stderr=%s", code, verifyOut, verifyErr)
	}
}

func TestPublishRestoreGenerationUsesCOSProtocolWithoutAdvancingCloudflare(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("dual-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("seed dual publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	source, _, exists, err := readLocalTargetGeneration(canonical, "cos")
	if err != nil || !exists || source.Generation != 1 {
		t.Fatalf("COS source generation=%#v exists=%v err=%v", source, exists, err)
	}
	var sourceRef publish.RefState
	for _, ref := range source.Refs {
		if strings.HasPrefix(ref.Name, "refs/sow/views/beta/") {
			sourceRef = ref
		}
	}
	if err := os.WriteFile(input, []byte("dual-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("second add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("second dual publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfBefore, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || cfBefore.Generation != 2 {
		t.Fatalf("CF before restore=%#v exists=%v err=%v", cfBefore, exists, err)
	}
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cos", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "target=cos") || !strings.Contains(stdout, "source_generation=1") {
		t.Fatalf("COS restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfAfter, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || cfAfter.Generation != cfBefore.Generation {
		t.Fatalf("CF advanced during COS restore before=%#v after=%#v exists=%v err=%v", cfBefore, cfAfter, exists, err)
	}
	cosAfter, _, exists, err := readLocalTargetGeneration(canonical, "cos")
	if err != nil || !exists || cosAfter.Generation != 3 || cosAfter.ParentGeneration != 2 {
		t.Fatalf("COS restored generation=%#v exists=%v err=%v", cosAfter, exists, err)
	}
	cosRemoteRef, _ := state.RemoteRef("cos", "beta", "assets", "all", "all")
	cosCommit, exists, err := canonical.Ref(cosRemoteRef)
	if err != nil || !exists || cosCommit.String() != sourceRef.Commit {
		t.Fatalf("COS restored ref=%s want=%s exists=%v err=%v", cosCommit, sourceRef.Commit, exists, err)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if got := string(transport.cosObjects[".sow/beta/pkg/latest"].body); got != "dual-one\n" {
		t.Fatalf("COS restored body=%q", got)
	}
	if got := string(transport.objects[".sow/beta/pkg/latest"].body); got != "dual-two\n" {
		t.Fatalf("CF body changed during COS restore=%q", got)
	}
	cosCheckpoint, err := publish.DecodeCheckpoint(transport.cosObjects[publish.CheckpointKey].body)
	if err != nil || cosCheckpoint.Generation != 3 {
		t.Fatalf("COS checkpoint=%#v err=%v", cosCheckpoint, err)
	}
}

func TestPublishRestoreCOSLockedCrashSurvivesCanonicalHeadAdvance(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(input, []byte("cos-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"},
		{"publish", "--view", "beta", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("seed command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	if err := os.WriteFile(input, []byte("cos-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"},
		{"publish", "--view", "beta", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("second command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	historical, err := loadHistoricalTargetPublication(canonical, "cos", 1)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "cos-restore-lock-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	client, err := newPublishTargetClient(cfg, "cos", "beta", false)
	if err != nil {
		t.Fatal(err)
	}
	inspection := filepath.Join(txDir, "inspect")
	if err := os.Mkdir(inspection, 0o700); err != nil {
		t.Fatal(err)
	}
	observation, err := observeRemoteTarget(t.Context(), canonical, client, "cos", inspection)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareHistoricalPublication(t.Context(), cfg, cfg, canonical, pool, cfg.Repos, "cos", historical, observation.parent, txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	lockedHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cos", lockedHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	boundHead, bound := publicationDesiredCommitFromTransactionID(publication.request.TransactionID)
	if !bound || boundHead != lockedHead {
		t.Fatalf("COS restore transaction head=%s want=%s bound=%v tx=%s", boundHead, lockedHead, bound, publication.request.TransactionID)
	}
	injected := false
	publisher := publish.NewCOSEdgeOnePublisher(publication.client.cos, publish.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhaseLocked && !injected {
			injected = true
			return errors.New("injected COS restore crash after lock")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected COS restore crash after lock") {
		t.Fatalf("COS restore lock crash err=%v", err)
	}
	if err := os.WriteFile(input, []byte("cos-three-local-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("advance canonical HEAD code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	advancedHead, err := canonical.HeadHash()
	if err != nil || advancedHead == lockedHead {
		t.Fatalf("canonical HEAD did not advance old=%s new=%s err=%v", lockedHead, advancedHead, err)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cos", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "generation=3") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("COS locked restore recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	current, _, exists, err := readLocalTargetGeneration(canonical, "cos")
	if err != nil || !exists || current.Generation != 3 || current.ParentGeneration != 2 || current.DesiredCommit != lockedHead.String() {
		t.Fatalf("COS recovered generation=%#v exists=%v err=%v", current, exists, err)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if got := string(transport.cosObjects[".sow/beta/pkg/latest"].body); got != "cos-one\n" {
		t.Fatalf("COS recovered restore body=%q", got)
	}
}

func TestPublishCOSLockedCrashSurvivesOtherTargetCanonicalCommit(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configText := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(input, []byte("ordinary-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("seed COS publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(input, []byte("ordinary-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("second add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("second COS publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(input, []byte("ordinary-three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("third add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "cos-ordinary-lock-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, cfg.Repos, "beta", txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	lockedHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cos", lockedHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	boundHead, bound := publicationDesiredCommitFromTransactionID(publication.request.TransactionID)
	if !bound || boundHead != lockedHead {
		t.Fatalf("ordinary COS transaction head=%s want=%s bound=%v tx=%s", boundHead, lockedHead, bound, publication.request.TransactionID)
	}
	injected := false
	publisher := publish.NewCOSEdgeOnePublisher(publication.client.cos, publish.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhaseLocked && !injected {
			injected = true
			return errors.New("injected ordinary COS crash after lock")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected ordinary COS crash after lock") {
		t.Fatalf("ordinary COS lock crash err=%v", err)
	}
	if code, stdout, stderr := run("publish", "--restore-generation", "1", "--target", "cos", "--config", configPath, "--workers", "2"); code != ExitConflict || !strings.Contains(stderr, "interrupted ordinary publication transaction") {
		t.Fatalf("restore takeover of ordinary transaction code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("other target publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	advancedHead, err := canonical.HeadHash()
	if err != nil || advancedHead == lockedHead {
		t.Fatalf("other target did not advance canonical HEAD old=%s new=%s err=%v", lockedHead, advancedHead, err)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("publish", "--view", "beta", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "generation=3") || !strings.Contains(stdout, "status=published") {
		t.Fatalf("ordinary COS recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	current, _, exists, err := readLocalTargetGeneration(canonical, "cos")
	if err != nil || !exists || current.Generation != 3 || current.DesiredCommit != lockedHead.String() {
		t.Fatalf("ordinary COS recovered generation=%#v exists=%v err=%v", current, exists, err)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if got := string(transport.cosObjects[".sow/beta/pkg/latest"].body); got != "ordinary-three\n" {
		t.Fatalf("ordinary COS recovered body=%q", got)
	}
}

func mustHeadHash(t *testing.T, canonical *state.Store) plumbing.Hash {
	t.Helper()
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestPublishCLIDefaultViewsRecoversCommittedAheadLatestBeforeBeta(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	first := filepath.Join(root, "first.txt")
	if err := os.WriteFile(first, []byte("beta-generation-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", first, "--config", configPath, "--repo", "assets", "--dest", "v1"); code != ExitOK {
		t.Fatalf("first add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("first promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("beta publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(second, []byte("latest-generation-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", second, "--config", configPath, "--repo", "assets", "--dest", "v2"); code != ExitOK {
		t.Fatalf("second add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("second promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-default-recovery-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, cfg.Repos, "latest", txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	if publication.request.Generation.Generation != 2 || publication.request.Generation.IntentView != "latest" {
		t.Fatalf("remote-ahead request generation=%d intent=%s", publication.request.Generation.Generation, publication.request.Generation.IntentView)
	}
	publisher, err := publication.client.publisher(root, filepath.Join(cfg.StatePath(), "publish-journal"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Run(t.Context(), publication.request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("remote-only latest result=%#v err=%v", result, err)
	}
	localGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || localGeneration.Generation != 1 || localGeneration.IntentView != "beta" {
		t.Fatalf("local target advanced before recovery generation=%#v exists=%v err=%v", localGeneration, exists, err)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run("publish", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || strings.Contains(stderr, "drift") {
		t.Fatalf("default recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	recovery := strings.Index(stdout, "target=cf view=latest generation=2")
	beta := strings.Index(stdout, "target=cf view=beta generation=3")
	if recovery < 0 || beta < 0 || recovery >= beta {
		t.Fatalf("latest was not recovered before beta release-order work: stdout=%s", stdout)
	}
	latestRemoteRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(latestRemoteRef); err != nil || !exists {
		t.Fatalf("latest remote ref exists=%v err=%v", exists, err)
	}
}

type secondGenerationPublishFixture struct {
	root        string
	configPath  string
	transport   *cloudProtocolTransport
	cfg         *config.Config
	canonical   *state.Store
	publication targetPublication
	txDir       string
}

func newSecondGenerationPublishFixture(t *testing.T) secondGenerationPublishFixture {
	return newSecondGenerationPublishFixtureWithOverwrite(t, false)
}

func newSecondGenerationPublishFixtureWithOverwrite(t *testing.T, overwrite bool) secondGenerationPublishFixture {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Main(args, &stdout, &stderr); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
	first := filepath.Join(root, "first.txt")
	if err := os.WriteFile(first, []byte("generation-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstDestination := "v1"
	if overwrite {
		firstDestination = "latest"
	}
	run("add", first, "--config", configPath, "--repo", "assets", "--dest", firstDestination)
	run("promote", "beta", "latest", "--config", configPath, "--repo", "assets")
	run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets")

	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	localETag, exists, err := readLocalTargetCheckpointETag(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("read generation-one checkpoint ETag exists=%v err=%v", exists, err)
	}
	transport.mutex.Lock()
	remoteParent := transport.objects[publish.CheckpointKey]
	transport.mutex.Unlock()
	if localETag != remoteParent.etag {
		t.Fatalf("local parent ETag=%q remote=%q", localETag, remoteParent.etag)
	}

	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(second, []byte("generation-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if overwrite {
		run("add", second, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace")
	} else {
		run("add", second, "--config", configPath, "--repo", "assets", "--dest", "v2")
	}
	run("promote", "beta", "latest", "--config", configPath, "--repo", "assets")

	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-generation-two-test-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, cfg.Repos, "latest", txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", desiredHead, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	if publication.request.Generation.Generation != 2 || publication.request.Expected.Generation != 1 || publication.request.Expected.ETag != localETag {
		t.Fatalf("generation-two request=%#v", publication.request)
	}
	return secondGenerationPublishFixture{
		root: root, configPath: configPath, transport: transport, cfg: cfg,
		canonical: canonical, publication: publication, txDir: txDir,
	}
}

func (fixture secondGenerationPublishFixture) recoverWithCLI(t *testing.T, putsBefore, purgesBefore int, remoteAlreadyCommitted bool) {
	t.Helper()
	if err := os.RemoveAll(fixture.txDir); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--view", "latest", "--target", "cf", "--config", fixture.configPath, "--repo", "assets", "--workers", "2"}, &stdout, &stderr)
	putsAfter, purgesAfter, _ := fixture.transport.counts()
	if code != ExitOK || !strings.Contains(stdout.String(), "generation=2") || !strings.Contains(stdout.String(), "status=published") {
		t.Fatalf("recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if remoteAlreadyCommitted && (putsAfter != putsBefore || purgesAfter != purgesBefore) {
		t.Fatalf("committed-ahead recovery repeated side effects puts=%d/%d purges=%d/%d", putsBefore, putsAfter, purgesBefore, purgesAfter)
	}
	if !remoteAlreadyCommitted && (putsAfter <= putsBefore || purgesAfter < purgesBefore) {
		t.Fatalf("locked recovery did not finish side effects puts=%d/%d purges=%d/%d", putsBefore, putsAfter, purgesBefore, purgesAfter)
	}
	localGeneration, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || localGeneration.Generation != 2 {
		t.Fatalf("local generation=%#v exists=%v err=%v", localGeneration, exists, err)
	}
	localETag, exists, err := readLocalTargetCheckpointETag(fixture.canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("read recovered checkpoint ETag exists=%v err=%v", exists, err)
	}
	fixture.transport.mutex.Lock()
	remoteETag := fixture.transport.objects[publish.CheckpointKey].etag
	fixture.transport.mutex.Unlock()
	if localETag != remoteETag || localETag == fixture.publication.request.Expected.ETag {
		t.Fatalf("recovered ETag local=%q remote=%q parent=%q", localETag, remoteETag, fixture.publication.request.Expected.ETag)
	}
}

func TestPublishCLIR2GenerationTwoRecoversLockedCheckpointWithPersistedParentETag(t *testing.T) {
	fixture := newSecondGenerationPublishFixture(t)
	failed := false
	publisher := publish.NewR2CloudflarePublisher(
		fixture.publication.client.r2,
		publish.DirectorySource{Root: fixture.root},
		filepath.Join(fixture.cfg.StatePath(), "publish-journal"),
		publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
			if phase == publish.PhaseLocked && !failed {
				failed = true
				return errors.New("injected generation-two lock crash")
			}
			return nil
		}},
	)
	if _, err := publisher.Run(t.Context(), fixture.publication.request); err == nil || !strings.Contains(err.Error(), "injected generation-two lock crash") {
		t.Fatalf("generation-two locked fixture err=%v", err)
	}
	fixture.transport.mutex.Lock()
	lockedObject := fixture.transport.objects[publish.CheckpointKey]
	fixture.transport.mutex.Unlock()
	locked, err := publish.DecodeCheckpoint(lockedObject.body)
	if err != nil || locked.Generation != 2 || locked.Phase != publish.PhaseLocked || lockedObject.etag == fixture.publication.request.Expected.ETag {
		t.Fatalf("locked checkpoint=%#v etag=%q parent=%q err=%v", locked, lockedObject.etag, fixture.publication.request.Expected.ETag, err)
	}
	putsBefore, purgesBefore, _ := fixture.transport.counts()
	fixture.recoverWithCLI(t, putsBefore, purgesBefore, false)
}

func TestPublishCLITamperedPurgeSidecarIsRecoveryConflictNotNetworkFailure(t *testing.T) {
	fixture := newSecondGenerationPublishFixtureWithOverwrite(t, true)
	if len(fixture.publication.request.Plan.PurgeURLs) == 0 {
		t.Fatal("overwrite fixture did not produce a purge closure")
	}
	failed := false
	publisher := publish.NewR2CloudflarePublisher(
		fixture.publication.client.r2,
		publish.DirectorySource{Root: fixture.root},
		filepath.Join(fixture.cfg.StatePath(), "publish-journal"),
		publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
			if phase == publish.PhasePurged && !failed {
				failed = true
				return errors.New("injected crash after durable purge evidence")
			}
			return nil
		}},
	).WithRequiredPurgeEvidence()
	result, err := publisher.Run(t.Context(), fixture.publication.request)
	if err == nil || !strings.Contains(err.Error(), "injected crash") || result.PurgeEvidencePath == "" {
		t.Fatalf("purge-evidence interruption result=%#v err=%v", result, err)
	}
	body, err := os.ReadFile(result.PurgeEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result.PurgeEvidencePath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(fixture.txDir); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--view", "latest", "--target", "cf", "--config", fixture.configPath, "--repo", "assets", "--workers", "2"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "load purge evidence") || strings.Contains(strings.ToLower(stderr.String()), "authentication") {
		t.Fatalf("tampered sidecar code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestPublishCLIR2GenerationTwoRecoversCommittedAheadWithPersistedParentETag(t *testing.T) {
	fixture := newSecondGenerationPublishFixture(t)
	publisher := publish.NewR2CloudflarePublisher(
		fixture.publication.client.r2,
		publish.DirectorySource{Root: fixture.root},
		filepath.Join(fixture.cfg.StatePath(), "publish-journal"),
		publish.Hooks{},
	)
	result, err := publisher.Run(t.Context(), fixture.publication.request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("remote generation-two publication result=%#v err=%v", result, err)
	}
	fixture.transport.mutex.Lock()
	committedObject := fixture.transport.objects[publish.CheckpointKey]
	fixture.transport.mutex.Unlock()
	committed, err := publish.DecodeCheckpoint(committedObject.body)
	if err != nil || committed.Generation != 2 || committed.Phase != publish.PhaseCheckpointCommitted || committedObject.etag == fixture.publication.request.Expected.ETag {
		t.Fatalf("committed checkpoint=%#v etag=%q parent=%q err=%v", committed, committedObject.etag, fixture.publication.request.Expected.ETag, err)
	}
	localGeneration, _, exists, err := readLocalTargetGeneration(fixture.canonical, "cf")
	if err != nil || !exists || localGeneration.Generation != 1 {
		t.Fatalf("local generation advanced before recovery generation=%#v exists=%v err=%v", localGeneration, exists, err)
	}
	putsBefore, purgesBefore, _ := fixture.transport.counts()
	fixture.recoverWithCLI(t, putsBefore, purgesBefore, true)
}

func TestPublishCLIR2RejectsSameGenerationCheckpointETagDrift(t *testing.T) {
	fixture := newSecondGenerationPublishFixture(t)
	fixture.transport.mutex.Lock()
	rewritten := fixture.transport.objects[publish.CheckpointKey]
	rewritten.etag = `"foreign-rewrite"`
	fixture.transport.objects[publish.CheckpointKey] = rewritten
	fixture.transport.mutex.Unlock()
	putsBefore, purgesBefore, _ := fixture.transport.counts()
	if err := os.RemoveAll(fixture.txDir); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--view", "latest", "--target", "cf", "--config", fixture.configPath, "--repo", "assets"}, &stdout, &stderr)
	putsAfter, purgesAfter, _ := fixture.transport.counts()
	if code != ExitConflict || !strings.Contains(stderr.String(), "local and remote generation differ") {
		t.Fatalf("ETag drift code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if putsAfter != putsBefore || purgesAfter != purgesBefore {
		t.Fatalf("ETag drift caused side effects puts=%d/%d purges=%d/%d", putsBefore, putsAfter, purgesBefore, purgesAfter)
	}
}

func protocolResponse(request *http.Request, status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d", status), Header: header,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request,
	}
}

func (transport *cloudProtocolTransport) counts() (puts, purges, cdnGets int) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	return transport.puts, transport.purges, transport.cdnGets
}

func TestPublishCLIUsesRealProviderProtocolAndAdvancesRemoteRefLast(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--workers", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	checkpointObject, checkpointExists := transport.objects[publish.CheckpointKey]
	_, pointerExists := transport.objects["pkg/latest"]
	archiveCount := 0
	for key := range transport.objects {
		if strings.HasPrefix(key, "objects/sha256/") {
			archiveCount++
		}
	}
	transport.mutex.Unlock()
	if !checkpointExists || !pointerExists || archiveCount != 1 || transport.purges != 1 {
		t.Fatalf("remote closure checkpoint=%v pointer=%v archives=%d purges=%d", checkpointExists, pointerExists, archiveCount, transport.purges)
	}
	checkpoint, err := publish.DecodeCheckpoint(checkpointObject.body)
	if err != nil || checkpoint.Phase != publish.PhaseCheckpointCommitted {
		t.Fatalf("checkpoint=%#v err=%v", checkpoint, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	desiredRef, _ := state.ViewRef("latest", "assets", "all", "all")
	desiredCommit, exists, err := canonical.Ref(desiredRef)
	if err != nil || !exists {
		t.Fatalf("desired ref exists=%v err=%v", exists, err)
	}
	remoteRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	remoteCommit, exists, err := canonical.Ref(remoteRef)
	if err != nil || !exists || remoteCommit != desiredCommit {
		t.Fatalf("remote ref=%s desired=%s exists=%v err=%v", remoteCommit, desiredCommit, exists, err)
	}
	localGenerationBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var localGeneration map[string]any
	if err := json.Unmarshal(localGenerationBody, &localGeneration); err != nil || uint64(localGeneration["generation"].(float64)) != checkpoint.Generation {
		t.Fatalf("local generation=%s err=%v", localGenerationBody, err)
	}

	putsBefore, purgesBefore, getsBefore := transport.counts()
	code, stdout, stderr = run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	putsAfter, purgesAfter, getsAfter := transport.counts()
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged preflight=ref-vector") || strings.Contains(stdout, "materialized view=") || putsAfter != putsBefore || purgesAfter != purgesBefore || getsAfter != getsBefore {
		t.Fatalf("replay code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d cdn=%d/%d", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}
	if err := canonical.RequireNoIncompleteTransactions(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishCLIUploadsRealAPTAndYUMGenerationClosures(t *testing.T) {
	root := nginxWorkerTempDir(t)
	writeRPMPackageTrustFixture(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	decodeFixture := func(source, destination string) {
		encoded, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, body, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	debPath := filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	rpmPath := filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
	decodeFixture("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64", debPath)
	decodeFixture("testdata/pgdg-redhat-nonfree-repo.rpm.b64", rpmPath)
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Publish Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "signing.key")
	if err := os.WriteFile(keyPath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	writeVerifyPublicKey(t, keyPath)
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("add DEB code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("add RPM code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") || !strings.Contains(stdout, "publish route-receipts view=beta receipts=2") {
		t.Fatalf("package publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	generation := "00000000000000000001"
	transport.mutex.Lock()
	_, aptPointer := transport.objects[".sow/beta/apt/test/dists/jammy/InRelease"]
	_, aptArchive := transport.objects[".sow/generations/"+generation+"/apt/apt/test/dists/jammy/InRelease"]
	yumRepomdObject, yumRepomd := transport.objects[".sow/generations/"+generation+"/yum/yum/test/x86_64/repodata/repomd.xml"]
	yumSignatureObject, yumSignature := transport.objects[".sow/generations/"+generation+"/yum/yum/test/x86_64/repodata/repomd.xml.asc"]
	legacyRepomd, legacyRepomdExists := transport.objects[".sow/beta/yum/test/x86_64/repodata/repomd.xml"]
	legacySignature, legacySignatureExists := transport.objects[".sow/beta/yum/test/x86_64/repodata/repomd.xml.asc"]
	mirrorObject, mirrorExists := transport.objects["_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"]
	purgeURLs := append([]string(nil), transport.purgeURLs...)
	checkpointBody := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	if !aptPointer || !aptArchive || !yumRepomd || !yumSignature || !legacyRepomdExists || !legacySignatureExists || !mirrorExists {
		t.Fatalf("closure apt_pointer=%v apt_archive=%v generation_repomd=%v generation_asc=%v legacy_repomd=%v legacy_asc=%v static_mirror=%v", aptPointer, aptArchive, yumRepomd, yumSignature, legacyRepomdExists, legacySignatureExists, mirrorExists)
	}
	if !bytes.Equal(legacyRepomd.body, yumRepomdObject.body) || !bytes.Equal(legacySignature.body, yumSignatureObject.body) {
		t.Fatal("YUM legacy aliases do not match their immutable generation pair")
	}
	joinedPurge := strings.Join(purgeURLs, "\n")
	if !strings.Contains(joinedPurge, "https://beta.test/apt/test/dists/jammy/InRelease") ||
		!strings.Contains(joinedPurge, "https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt") ||
		!strings.Contains(joinedPurge, "https://beta.test/yum/test/x86_64/repodata/repomd.xml") ||
		!strings.Contains(joinedPurge, "https://beta.test/yum/test/x86_64/repodata/repomd.xml.asc") {
		t.Fatalf("purge closure=%v", purgeURLs)
	}
	checkpoint, err := publish.DecodeCheckpoint(checkpointBody)
	if err != nil || checkpoint.Generation != 1 {
		t.Fatalf("checkpoint=%#v err=%v", checkpoint, err)
	}
	generationKey, _ := publish.GenerationKey(1)
	transport.mutex.Lock()
	generationBody := append([]byte(nil), transport.objects[generationKey].body...)
	transport.mutex.Unlock()
	targetGeneration, err := publish.DecodeTargetGeneration(generationBody)
	if err != nil || len(targetGeneration.Refs) != 2 || len(targetGeneration.Channels) != 1 {
		t.Fatalf("target generation refs=%d channels=%d err=%v body=%s", len(targetGeneration.Refs), len(targetGeneration.Channels), err, generationBody)
	}
	channel := targetGeneration.Channels[0]
	if channel.View != "beta" || channel.Repo != "rpm-test" || channel.OS != "el10" || channel.Arch != "x86_64" || channel.Generation != 1 || channel.RemoteKey != ".sow/channels/beta/rpm-test/el10/x86_64.json" || channel.LegacyRoot != "yum/test/x86_64" {
		t.Fatalf("target generation channel=%#v", channel)
	}
	expectedChannelBody, err := channel.CanonicalBody()
	expectedMirrorBody := []byte("https://beta.test/_sow/v1/g/00000000000000000001/yum/test/x86_64/\n")
	if err != nil || !bytes.Equal(mirrorObject.body, expectedMirrorBody) || mirrorObject.sha != digestBytesCLI(expectedMirrorBody) {
		t.Fatalf("static mirror body=%s sha=%s expected=%s channel=%#v err=%v", mirrorObject.body, mirrorObject.sha, expectedMirrorBody, channel, err)
	}
	localChannelBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "channels", "beta", "rpm-test", "el10", "x86_64.json"))
	if err != nil || !bytes.Equal(localChannelBody, expectedChannelBody) {
		t.Fatalf("local canonical channel body=%s expected=%s err=%v", localChannelBody, expectedChannelBody, err)
	}
	localServingRoot := filepath.Join(root, ".sow", "materialized", "beta")
	localMirror := filepath.Join(localServingRoot, "_sow", "v1", "mirrorlist", "beta", "rpm-test", "el10", "x86_64.txt")
	localMirrorBody, err := os.ReadFile(localMirror)
	if err != nil || !bytes.HasPrefix(localMirrorBody, []byte("https://beta.test/_sow/v1/g/")) {
		t.Fatalf("local strong YUM mirrorlist=%s err=%v", localMirrorBody, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ledgers := loadRouteLedgersForTest(t, canonical, localServingRoot, "beta")
	if len(ledgers) != 2 {
		t.Fatalf("publish did not commit the APT and YUM read capabilities: %+v", ledgers)
	}
	for _, ledger := range ledgers {
		assertRouteLedgerValidForTest(t, root, localServingRoot, ledger)
	}
	code, nginxOutput, nginxErr := run("materialize", "beta", "--config", configPath, "--repo", "deb-test", "--repo", "rpm-test", "--nginx-include", "-", "--workers", "1", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(nginxOutput, "location ^~ /apt/test/") || !strings.Contains(nginxOutput, "location ^~ /yum/test/x86_64/") || nginxErr != "" {
		t.Fatalf("published routes are not Nginx-admissible code=%d stdout=%s stderr=%s", code, nginxOutput, nginxErr)
	}
	if code, promoteOutput, promoteErr := run("promote", "beta", "latest", "--config", configPath, "--repo", "deb-test", "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote latest before fsck code=%d stdout=%s stderr=%s", code, promoteOutput, promoteErr)
	}
	code, latestOutput, latestErr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(latestOutput, "status=published") || !strings.Contains(latestOutput, "publish route-receipts view=latest receipts=2") {
		t.Fatalf("publish latest before fsck code=%d stdout=%s stderr=%s", code, latestOutput, latestErr)
	}
	code, fsckOutput, fsckErr := run("fsck", "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(fsckOutput, "fsck clean") || fsckErr != "" {
		t.Fatalf("published routes do not pass fsck code=%d stdout=%s stderr=%s", code, fsckOutput, fsckErr)
	}
	localTarget, err := serving.NewTargetIdentity("beta", ".sow/materialized/beta", "https://beta.test")
	if err != nil {
		t.Fatal(err)
	}
	localServingChannel := filepath.Join(root, ".sow", "state", filepath.FromSlash(serving.ChannelStatePath(serving.Channel{
		TargetID: localTarget.ID, View: "beta", Repo: "rpm-test", OS: "el10", Arch: "x86_64",
	})))
	localServingChannelBody, err := os.ReadFile(localServingChannel)
	if err != nil {
		t.Fatalf("local serving channel ledger missing: %v", err)
	}
	decodedLocalChannel, err := serving.DecodeChannel(localServingChannelBody)
	if err != nil {
		t.Fatal(err)
	}
	localGenerationPath := filepath.Join(root, ".sow", "state", filepath.FromSlash(path.Join("serving/yum/generations", decodedLocalChannel.Generation, "beta/rpm-test/el10/x86_64.json")))
	localGenerationBody, err := os.ReadFile(localGenerationPath)
	if err != nil {
		t.Fatal(err)
	}
	decodedLocalGeneration, err := serving.DecodeGeneration(localGenerationBody)
	if err != nil {
		t.Fatal(err)
	}
	_, localPackageKeyringSHA256, err := loadRPMPackageKeyring(configPath, "package-trust.asc")
	if err != nil {
		t.Fatal(err)
	}
	journal := localServingJournal{
		Schema: localServingJournalSchema, Phase: localServingStateCommitted, TargetRoot: ".sow/materialized/beta",
		PackageKeyringSHA256: localPackageKeyringSHA256, Generation: decodedLocalGeneration, Channel: decodedLocalChannel,
	}
	journal.ID = localServingJournalID(journal)
	if err := createLocalServingJournal(filepath.Join(root, ".sow"), journal); err != nil {
		t.Fatal(err)
	}
	putsBefore, purgesBefore, getsBefore := transport.counts()
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--recover")
	putsAfter, purgesAfter, getsAfter := transport.counts()
	if code != ExitOK || !strings.Contains(stdout, "recovered local-serving=") || !strings.Contains(stdout, "status=unchanged preflight=ref-vector") || strings.Contains(stdout, "materialized view=") ||
		putsAfter != putsBefore || purgesAfter != purgesBefore || getsAfter != getsBefore {
		t.Fatalf("strong-YUM no-op code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d gets=%d/%d", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}
	if code, stdout, stderr = run("promote", "beta", "stable", "--config", configPath, "--repo", "deb-test", "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote stable code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr = run("publish", "--view", "stable", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("publish stable code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	wrongTrust, err := os.ReadFile(filepath.Join(root, "signing.key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-trust.asc"), wrongTrust, 0o644); err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	checkpointBefore := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	putsBefore, purgesBefore, _ = transport.counts()
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2")
	putsAfter, purgesAfter, getsAfter = transport.counts()
	transport.mutex.Lock()
	checkpointAfter := append([]byte(nil), transport.objects[publish.CheckpointKey].body...)
	transport.mutex.Unlock()
	if code != ExitVerification || !strings.Contains(stderr, "reachable RPM package trust") || putsAfter != putsBefore || purgesAfter != purgesBefore || !bytes.Equal(checkpointBefore, checkpointAfter) {
		t.Fatalf("dropped inherited signer publish code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d gets_after=%d checkpoint_changed=%t", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, getsAfter, !bytes.Equal(checkpointBefore, checkpointAfter))
	}
}

func TestPublishCLIYUMSnapshotUsesExactIntentStableRouteAndServerSideCopy(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "package.rpm")
	if err := os.WriteFile(rpmPath, rpmBody, 0o444); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	publicKeyPath := writeVerifyPublicKey(t, keyPath)
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousClient
		verificationHTTPClient = previousVerificationClient
	})
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("stable seed publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("el10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("snapshot promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "view=snapshot snapshot="+snapshotID) || !strings.Contains(stdout, "status=published") {
		t.Fatalf("snapshot publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	copies := transport.copies
	var routeBody, generationBody []byte
	for key, object := range transport.objects {
		if key == ".sow/snapshots/"+snapshotID+".json" {
			routeBody = append([]byte(nil), object.body...)
		}
	}
	checkpoint, checkpointExists := transport.objects[publish.CheckpointKey]
	if checkpointExists {
		decoded, decodeErr := publish.DecodeCheckpoint(checkpoint.body)
		if decodeErr == nil {
			key, _ := publish.GenerationKey(decoded.Generation)
			generationBody = append([]byte(nil), transport.objects[key].body...)
		}
	}
	putsBefore, copiesBefore, purgesBefore := transport.puts, transport.copies, transport.purges
	transport.mutex.Unlock()
	if copies < 1 || len(routeBody) == 0 || len(generationBody) == 0 {
		t.Fatalf("snapshot closure copies=%d route=%s generation=%s", copies, routeBody, generationBody)
	}
	generation, err := publish.DecodeTargetGeneration(generationBody)
	if err != nil || generation.IntentView != "snapshot" || generation.IntentSnapshot != snapshotID {
		t.Fatalf("snapshot generation intent=%#v err=%v", generation, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	remoteRef, _ := state.RemoteRef("cf", snapshotID, "rpm-test", "el10", "x86_64")
	if _, exists, err := canonical.Ref(remoteRef); err != nil || !exists {
		t.Fatalf("snapshot remote ref exists=%v err=%v", exists, err)
	}
	code, stdout, stderr = run("verify", "--layer", "all", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-public-key-file", publicKeyPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || !strings.Contains(stdout, "CLIENT_EVIDENCE_ACCEPTED") || !strings.Contains(stdout, `client="dnf"`) {
		t.Fatalf("snapshot L1-L4 verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	intentPlan := filepath.Join(root, ".sow", "state", "remotes", "cf", "intents", "snapshots", snapshotID, "plan.json")
	if _, err := os.Stat(intentPlan); err != nil {
		t.Fatalf("snapshot intent plan missing: %v", err)
	}

	// Bypass Store.AdvanceRef to model on-disk Git metadata tampering. Even
	// when the later aggregate commit contains identical manifest bytes, L2
	// must reject movement of the immutable snapshot ref by commit identity.
	snapshotRef, _ := state.SnapshotRef(snapshotID, "rpm-test", "el10", "x86_64")
	originalSnapshotCommit, exists, err := canonical.Ref(snapshotRef)
	if err != nil || !exists {
		t.Fatalf("snapshot ref before drift exists=%v err=%v", exists, err)
	}
	laterCommit, err := canonical.HeadHash()
	if err != nil || laterCommit == originalSnapshotCommit {
		t.Fatalf("need a later aggregate commit for drift test head=%s snapshot=%s err=%v", laterCommit, originalSnapshotCommit, err)
	}
	stateRepo, err := git.PlainOpen(filepath.Join(root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stateRepo.Storer.SetReference(plumbing.NewHashReference(snapshotRef, laterCommit)); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test")
	if code != ExitVerification || !strings.Contains(stdout, "SNAPSHOT_IMMUTABLE_REF_DRIFT") {
		t.Fatalf("snapshot immutable ref drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := stateRepo.Storer.SetReference(plumbing.NewHashReference(snapshotRef, originalSnapshotCommit)); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2")
	transport.mutex.Lock()
	putsAfter, copiesAfter, purgesAfter := transport.puts, transport.copies, transport.purges
	transport.mutex.Unlock()
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged") || putsAfter != putsBefore || copiesAfter != copiesBefore || purgesAfter != purgesBefore {
		t.Fatalf("snapshot replay code=%d stdout=%s stderr=%s puts=%d/%d copies=%d/%d purges=%d/%d", code, stdout, stderr, putsBefore, putsAfter, copiesBefore, copiesAfter, purgesBefore, purgesAfter)
	}
	// A later view publication advances the bucket-global checkpoint. The
	// intent-scoped snapshot checkpoint/plan and immutable generation must
	// remain independently auditable through a runtime token route.
	if code, stdout, stderr = run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("later view publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	coverageStage := filepath.Join(root, ".sow", "tmp", "snapshot-test-inventory.coverage")
	if err := os.MkdirAll(filepath.Dir(coverageStage), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coverageStage, []byte(remoteInventoryComplete), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.coverage"): coverageStage}, "test: inventory already audited complete"); err != nil {
		t.Fatalf("mark snapshot inventory complete: %v", err)
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("latest channel immediate L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	latestMirrorKey := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	transport.mutex.Lock()
	latestMirror, latestMirrorExists := transport.objects[latestMirrorKey]
	delete(transport.objects, latestMirrorKey)
	transport.mutex.Unlock()
	if !latestMirrorExists {
		t.Fatalf("latest publication did not create %s", latestMirrorKey)
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "REMOTE_CHANNEL_MISSING") {
		t.Fatalf("missing latest mirrorlist L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	transport.objects[latestMirrorKey] = latestMirror
	transport.mutex.Unlock()
	tokenPath := filepath.Join(root, "snapshot-pro-token")
	if err := os.WriteFile(tokenPath, []byte(verifyTestProToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("verify", "--layer", "L2,L3,L4", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-public-key-file", publicKeyPath, "--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || strings.Contains(stdout+stderr, verifyTestProToken) {
		t.Fatalf("retained snapshot token verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	previousNow := timeNowUTC
	timeNowUTC = func() time.Time { return time.Now().UTC().AddDate(0, 7, 0) }
	code, stdout, stderr = run("publish", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2")
	timeNowUTC = previousNow
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("snapshot expiration publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	retired, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("retired snapshot parent exists=%v err=%v", exists, err)
	}
	for _, ref := range retired.Refs {
		if strings.HasPrefix(ref.Name, "refs/sow/snapshots/"+snapshotID+"/") {
			t.Fatalf("expired snapshot ref remained in parent generation: %#v", ref)
		}
	}
	transport.mutex.Lock()
	_, routeStillExists := transport.objects[".sow/snapshots/"+snapshotID+".json"]
	copiesBeforeRestore, purgesBeforeRestore, basicBeforeRestore := transport.copies, transport.purges, transport.basicGets
	transport.mutex.Unlock()
	if routeStillExists {
		t.Fatal("expired snapshot route remains before restore")
	}
	retentionPlanBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "intents", "views", "stable", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	retentionPlan, err := publish.DecodePlan(retentionPlanBody)
	if err != nil || len(retentionPlan.VerifyAbsent) == 0 || len(retentionPlan.Probes) != 1 {
		t.Fatalf("retention plan positive/negative closure probes=%#v absent=%#v err=%v", retentionPlan.Probes, retentionPlan.VerifyAbsent, err)
	}
	wantedAbsentURL := "https://repo.test/pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/_route.json"
	foundAbsentURL := false
	for _, expectation := range retentionPlan.VerifyAbsent {
		foundAbsentURL = foundAbsentURL || expectation.URL == wantedAbsentURL
	}
	if !foundAbsentURL {
		t.Fatalf("retention plan does not bind deleted snapshot route %s: %#v", wantedAbsentURL, retentionPlan.VerifyAbsent)
	}

	// Standalone L3 must replay the committed negative expectation. A stale
	// route that still returns 200 is drift; after eviction, 404 is success.
	transport.mutex.Lock()
	transport.objects[".sow/snapshots/"+snapshotID+".json"] = protocolObject{body: append([]byte(nil), routeBody...), sha: digestBytesCLI(routeBody), etag: `"stale-route"`}
	absenceGetsBefore := transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "CDN_ABSENCE_DRIFT") {
		t.Fatalf("stale deleted route L3 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	delete(transport.objects, ".sow/snapshots/"+snapshotID+".json")
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	transport.mutex.Lock()
	absenceGetsAfter := transport.cdnGets
	transport.mutex.Unlock()
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || absenceGetsAfter <= absenceGetsBefore {
		t.Fatalf("deleted route 404 L3 code=%d stdout=%s stderr=%s gets=%d/%d", code, stdout, stderr, absenceGetsBefore, absenceGetsAfter)
	}
	code, stdout, stderr = run("publish", "--restore-generation", strconv.FormatUint(generation.Generation, 10), "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "intent="+snapshotID) || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("historical snapshot restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	restored, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || restored.ParentGeneration != retired.Generation || restored.Generation != retired.Generation+1 || restored.IntentView != "snapshot" || restored.IntentSnapshot != snapshotID {
		t.Fatalf("restored snapshot generation=%#v parent=%#v exists=%v err=%v", restored, retired, exists, err)
	}
	localSnapshotCommit, localSnapshotExists, err := canonical.Ref(snapshotRef)
	if err != nil || !localSnapshotExists || localSnapshotCommit != originalSnapshotCommit {
		t.Fatalf("snapshot restore moved immutable local ref got=%s want=%s exists=%v err=%v", localSnapshotCommit, originalSnapshotCommit, localSnapshotExists, err)
	}
	remoteSnapshotCommit, remoteSnapshotExists, err := canonical.Ref(remoteRef)
	if err != nil || !remoteSnapshotExists || remoteSnapshotCommit != originalSnapshotCommit {
		t.Fatalf("snapshot remote ref got=%s want=%s exists=%v err=%v", remoteSnapshotCommit, originalSnapshotCommit, remoteSnapshotExists, err)
	}
	transport.mutex.Lock()
	restoredRoute := append([]byte(nil), transport.objects[".sow/snapshots/"+snapshotID+".json"].body...)
	copiesAfterRestore, purgesAfterRestore, basicAfterRestore := transport.copies, transport.purges, transport.basicGets
	transport.mutex.Unlock()
	if !bytes.Contains(restoredRoute, []byte(fmt.Sprintf(`"generation":"%020d"`, restored.Generation))) || copiesAfterRestore <= copiesBeforeRestore || purgesAfterRestore <= purgesBeforeRestore || basicAfterRestore <= basicBeforeRestore {
		t.Fatalf("snapshot restore closure route=%s copies=%d/%d purges=%d/%d basic=%d/%d", restoredRoute, copiesBeforeRestore, copiesAfterRestore, purgesBeforeRestore, purgesAfterRestore, basicBeforeRestore, basicAfterRestore)
	}
	code, stdout, stderr = run("verify", "--layer", "L2,L3,L4", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-public-key-file", publicKeyPath, "--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || strings.Contains(stdout+stderr, verifyTestProToken) {
		t.Fatalf("restored snapshot verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	stableGetsBefore := transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L2,L3", "--view", "stable", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	transport.mutex.Lock()
	stableGetsAfter := transport.cdnGets
	transport.mutex.Unlock()
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || strings.Contains(stdout, "CDN_ABSENCE_DRIFT") || stableGetsAfter <= stableGetsBefore {
		t.Fatalf("stable verify after snapshot restore code=%d stdout=%s stderr=%s gets=%d/%d", code, stdout, stderr, stableGetsBefore, stableGetsAfter)
	}
	transport.mutex.Lock()
	putsBeforeReplay, copiesBeforeReplay, purgesBeforeReplay := transport.puts, transport.copies, transport.purges
	transport.mutex.Unlock()
	code, stdout, stderr = run("publish", "--restore-generation", strconv.FormatUint(generation.Generation, 10), "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	transport.mutex.Lock()
	putsAfterReplay, copiesAfterReplay, purgesAfterReplay := transport.puts, transport.copies, transport.purges
	transport.mutex.Unlock()
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged") || putsAfterReplay != putsBeforeReplay || copiesAfterReplay != copiesBeforeReplay || purgesAfterReplay != purgesBeforeReplay {
		t.Fatalf("snapshot restore replay code=%d stdout=%s stderr=%s puts=%d/%d copies=%d/%d purges=%d/%d", code, stdout, stderr, putsBeforeReplay, putsAfterReplay, copiesBeforeReplay, copiesAfterReplay, purgesBeforeReplay, purgesAfterReplay)
	}
	if code, _, stderr := run("publish", "--view", "stable", "--snapshot", snapshotID); code != ExitUsage || !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("view/snapshot conflict code=%d stderr=%s", code, stderr)
	}
}

func TestPublishCLIAssetOnlyChangeDoesNotTouchYUMClosures(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishMultiLeafPackageAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
	if err := os.WriteFile(rpmPath, rpmBody, 0o444); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	writeVerifyPublicKey(t, keyPath)
	assetPath := filepath.Join(root, "latest.txt")
	if err := os.WriteFile(assetPath, []byte("asset-generation-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("RPM add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	for _, arch := range []string{"aarch64", "x86_64"} {
		ref, _ := state.ViewRef("beta", "rpm-test", "el10", arch)
		if _, exists, err := canonical.Ref(ref); err != nil || !exists {
			t.Fatalf("YUM leaf %s exists=%v err=%v", arch, exists, err)
		}
	}
	if code, stdout, stderr := run("add", assetPath, "--config", configPath, "--repo", "assets", "--dest", "latest", "--workers", "2"); code != ExitOK {
		t.Fatalf("asset add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("initial publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	transport.mutex.Lock()
	putOffset, purgeOffset, cdnOffset := len(transport.putKeys), len(transport.purgeURLs), len(transport.cdnURLs)
	transport.mutex.Unlock()
	if err := os.WriteFile(assetPath, []byte("asset-generation-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", assetPath, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace", "--workers", "2"); code != ExitOK {
		t.Fatalf("asset replace code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "view=beta generation=2") || !strings.Contains(stdout, "status=published") {
		t.Fatalf("asset-only publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	putKeys := append([]string(nil), transport.putKeys[putOffset:]...)
	purgeURLs := append([]string(nil), transport.purgeURLs[purgeOffset:]...)
	cdnURLs := append([]string(nil), transport.cdnURLs[cdnOffset:]...)
	transport.mutex.Unlock()
	for kind, values := range map[string][]string{"PUT": putKeys, "purge": purgeURLs, "verify": cdnURLs} {
		for _, value := range values {
			if isYUMProtocolPath(value) {
				t.Fatalf("asset-only generation performed YUM %s side effect %q; puts=%v purges=%v verifies=%v", kind, value, putKeys, purgeURLs, cdnURLs)
			}
		}
	}
	if len(putKeys) == 0 || len(purgeURLs) == 0 || len(cdnURLs) == 0 {
		t.Fatalf("asset-only generation did not exercise publication side effects puts=%v purges=%v verifies=%v", putKeys, purgeURLs, cdnURLs)
	}

	// Rotate the configured key bytes in place without changing the config
	// path or any canonical refs. The no-change preflight must notice the trust
	// identity drift, and an asset-only retry must fail before the remote saga
	// because it cannot re-sign the carried YUM closure.
	liveSignaturePath := filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64", "repodata", "repomd.xml.asc")
	liveSignatureBefore, err := os.ReadFile(liveSignaturePath)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeyPath := writePublishTestPrivateKey(t, t.TempDir())
	for _, replacement := range []struct {
		source, target string
		mode           os.FileMode
	}{{rotatedKeyPath, keyPath, 0o600}, {rotatedKeyPath + ".pub", keyPath + ".pub", 0o644}} {
		body, err := os.ReadFile(replacement.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replacement.target, body, replacement.mode); err != nil {
			t.Fatal(err)
		}
	}
	putsBeforeRotation, purgesBeforeRotation, getsBeforeRotation := transport.counts()
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	putsAfterRotation, purgesAfterRotation, getsAfterRotation := transport.counts()
	if code != ExitConflict || !strings.Contains(stderr, "repository signing key changed") || strings.Contains(stdout, "status=unchanged preflight=ref-vector") {
		t.Fatalf("asset-only key rotation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if putsAfterRotation != putsBeforeRotation || purgesAfterRotation != purgesBeforeRotation || getsAfterRotation != getsBeforeRotation {
		t.Fatalf("rejected key rotation reached saga puts=%d/%d purges=%d/%d cdn=%d/%d", putsBeforeRotation, putsAfterRotation, purgesBeforeRotation, purgesAfterRotation, getsBeforeRotation, getsAfterRotation)
	}

	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code == ExitOK || !strings.Contains(stdout, "REMOTE_REPOSITORY_KEY_DRIFT") {
		t.Fatalf("repository-key drift verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// The single-key contract also rejects a nominally full view republish: the
	// target may carry other views/snapshots, and online replacement cannot make
	// all client-visible signatures and trust distribution atomic.
	putsBeforeFullRotation, purgesBeforeFullRotation, getsBeforeFullRotation := transport.counts()
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2")
	putsAfterFullRotation, purgesAfterFullRotation, getsAfterFullRotation := transport.counts()
	if code != ExitConflict || !strings.Contains(stderr, "repository signing key changed") {
		t.Fatalf("full online key-rotation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if putsAfterFullRotation != putsBeforeFullRotation || purgesAfterFullRotation != purgesBeforeFullRotation || getsAfterFullRotation != getsBeforeFullRotation {
		t.Fatalf("full rejected rotation reached saga puts=%d/%d purges=%d/%d cdn=%d/%d", putsBeforeFullRotation, putsAfterFullRotation, purgesBeforeFullRotation, purgesAfterFullRotation, getsBeforeFullRotation, getsAfterFullRotation)
	}
	liveSignatureAfter, err := os.ReadFile(liveSignaturePath)
	if err != nil || !bytes.Equal(liveSignatureBefore, liveSignatureAfter) {
		t.Fatalf("rejected rotation changed directly hosted YUM signature err=%v", err)
	}
}

// Test fixtures exercise OpenPGP semantics rather than RSA strength. Keeping
// fixture keys at 1024 bits avoids spending the full-suite budget repeatedly
// generating short-lived 2048-bit encryption subkeys under Go's FIPS backend.
const testOpenPGPRSABits = 1024

func writePublishTestPrivateKey(t *testing.T, root string) string {
	t.Helper()
	writeRPMPackageTrustFixture(t, root)
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Publish Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "signing.key")
	if err := os.WriteFile(keyPath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	writeVerifyPublicKey(t, keyPath)
	return keyPath
}

func isYUMProtocolPath(value string) bool {
	return strings.Contains(value, "yum/test/") ||
		strings.Contains(value, "/yum/yum/test/") ||
		strings.Contains(value, "/rpm-test/") ||
		strings.Contains(value, ".sow/channels/")
}

const publishAssetConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`

const publishMultiLeafPackageAssetConfig = `schema: sow/v1
state: {}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: rpm-test
    type: yum
    path: "yum/test/{arch}"
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`

const publishPackageConfig = `schema: sow/v1
state: {}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: deb-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: rpm-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`

const publishRestorePackageConfig = `schema: sow/v1
state: {}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: deb-restore
    type: apt
    path: apt/restore
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: rpm-restore
    type: yum
    path: yum/restore/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`

const publishTopologyRestoreConfig = `schema: sow/v1
state: {}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: release, mutable_paths: [latest]}
  - id: deb-topology
    type: apt
    path: apt/topology
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
  - id: rpm-topology
    type: yum
    path: yum/topology/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`

func writeRestoreRPMFixture(t *testing.T, root, version string) string {
	t.Helper()
	// Restore tests need two byte-distinct, genuinely signed RPMs so the
	// package-trust preflight is exercised during both publication generations.
	// Historical CentOS fixtures are intentionally used because their signer
	// bundles also exercise signature-time (rather than observation-time) key
	// validity.
	source := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-4-0.1.x86_64.rpm")
	if version == "2.0.0" {
		source = filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-5-0.0.el5.centos.2.x86_64.rpm")
	}
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, filepath.Base(source))
	if err := os.WriteFile(filename, body, 0o444); err != nil {
		t.Fatal(err)
	}
	return filename
}
