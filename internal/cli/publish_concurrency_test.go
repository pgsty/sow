package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type blockingCFCheckpointTransport struct {
	base        http.RoundTripper
	calls       atomic.Int64
	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
}

// These integration tests execute complete dual-target CLI publications under
// the race detector. Progress is synchronized by explicit transport and
// checkpoint events; the timeout is only a deadlock guard and must tolerate
// race-instrumented filesystem and cryptographic work on a loaded runner.
const publishConcurrencyProgressTimeout = 30 * time.Second

func (transport *blockingCFCheckpointTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	checkpointRead := request.Method == http.MethodGet && strings.TrimPrefix(request.URL.Path, "/") == publish.CheckpointKey
	if checkpointRead && request.URL.Host == "repo-bucket.storage.test" {
		transport.calls.Add(1)
		transport.startedOnce.Do(func() { close(transport.started) })
		select {
		case <-transport.release:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}
	return transport.base.RoundTrip(request)
}

func TestRunBoundedOrderedSharesWorkerBudgetAndSorts(t *testing.T) {
	const budget = 4
	started := make(chan int, 8)
	release := make(chan struct{})
	var active atomic.Int64
	var peak atomic.Int64
	tasks := make([]boundedOrderedTask[string], 0, 8)
	for index := 7; index >= 0; index-- {
		key := fmt.Sprintf("task-%02d", index)
		tasks = append(tasks, boundedOrderedTask[string]{key: key, run: func(_ context.Context, workers int) (string, error) {
			current := active.Add(1)
			for observed := peak.Load(); current > observed && !peak.CompareAndSwap(observed, current); observed = peak.Load() {
			}
			started <- workers
			<-release
			active.Add(-1)
			return key, nil
		}})
	}
	type outcome struct {
		values []string
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		values, err := runBoundedOrdered(context.Background(), budget, tasks)
		done <- outcome{values: values, err: err}
	}()
	for range budget {
		select {
		case inner := <-started:
			if inner != 1 {
				t.Fatalf("inner worker allocation=%d, want 1 with %d concurrent tasks", inner, budget)
			}
		case <-time.After(time.Second):
			t.Fatal("bounded publication tasks did not reach configured concurrency")
		}
	}
	select {
	case <-started:
		t.Fatal("publication preparation exceeded its global worker budget")
	case <-time.After(50 * time.Millisecond):
	}
	if got := peak.Load(); got != budget {
		t.Fatalf("peak publication task concurrency=%d, want %d", got, budget)
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	for index, value := range result.values {
		want := fmt.Sprintf("task-%02d", index)
		if value != want {
			t.Fatalf("result[%d]=%q, want stable order %q", index, value, want)
		}
	}

	var inner int
	values, err := runBoundedOrdered(context.Background(), budget, []boundedOrderedTask[string]{{
		key: "only", run: func(_ context.Context, workers int) (string, error) {
			inner = workers
			return "only", nil
		},
	}})
	if err != nil || len(values) != 1 || inner != budget {
		t.Fatalf("single task did not receive full budget: values=%v inner=%d err=%v", values, inner, err)
	}
}

func TestTargetPublicationSequencesAdvanceAcrossIntentsWithoutWaitingForSlowSibling(t *testing.T) {
	releaseCF := make(chan struct{})
	cfStarted := make(chan struct{})
	cosStable := make(chan struct{})
	type result struct {
		outcomes []targetPublicationSequenceOutcome
		err      error
	}
	done := make(chan result, 1)
	go func() {
		outcomes, err := runTargetPublicationSequencesConcurrently(
			context.Background(), []string{"cf", "cos"}, t.TempDir(), 1,
			func(_ context.Context, target, _ string, workers int, output io.Writer) error {
				if workers != 1 {
					return fmt.Errorf("inner workers=%d", workers)
				}
				if target == "cf" {
					close(cfStarted)
					<-releaseCF
					fmt.Fprintln(output, "cf/beta")
					return nil
				}
				for _, intent := range []string{"beta", "latest", "stable"} {
					fmt.Fprintf(output, "cos/%s\n", intent)
				}
				close(cosStable)
				return nil
			},
		)
		done <- result{outcomes: outcomes, err: err}
	}()
	select {
	case <-cfStarted:
	case <-time.After(time.Second):
		t.Fatal("CF target sequence did not start")
	}
	select {
	case <-cosStable:
	case <-time.After(time.Second):
		t.Fatal("COS did not advance through stable while CF remained blocked")
	}
	select {
	case result := <-done:
		t.Fatalf("sequence join returned while CF remained blocked: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCF)
	resultValue := <-done
	if resultValue.err != nil || len(resultValue.outcomes) != 2 {
		t.Fatalf("sequence outcomes=%+v err=%v", resultValue.outcomes, resultValue.err)
	}
	if resultValue.outcomes[0].target != "cf" || string(resultValue.outcomes[0].output) != "cf/beta\n" ||
		resultValue.outcomes[1].target != "cos" || string(resultValue.outcomes[1].output) != "cos/beta\ncos/latest\ncos/stable\n" {
		t.Fatalf("sequence output order/content=%+v", resultValue.outcomes)
	}
}

func TestTargetPublicationPreparationIsConcurrentIsolatedAndFailureIndependent(t *testing.T) {
	const budget = 4
	txDir := t.TempDir()
	cfStarted := make(chan struct{})
	cosStarted := make(chan struct{})
	releaseCF := make(chan struct{})
	cfFailure := errors.New("injected cf observation failure")
	type outcome struct {
		results []preparedTargetPublication
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := prepareTargetPublicationsConcurrently(
			context.Background(), []string{"cf", "cos"}, txDir, budget,
			func(_ context.Context, target, targetDir string, workers int) (targetPublication, error) {
				if workers != budget/2 {
					return targetPublication{}, fmt.Errorf("target %s workers=%d", target, workers)
				}
				info, err := os.Lstat(targetDir)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
					return targetPublication{}, fmt.Errorf("target %s workspace is unsafe: mode=%v err=%v", target, info, err)
				}
				marker := filepath.Join(targetDir, "marker")
				if err := os.WriteFile(marker, []byte(target), 0o600); err != nil {
					return targetPublication{}, err
				}
				switch target {
				case "cf":
					close(cfStarted)
					<-releaseCF
					return targetPublication{}, cfFailure
				case "cos":
					close(cosStarted)
					return targetPublication{target: target}, nil
				default:
					return targetPublication{}, fmt.Errorf("unexpected target %s", target)
				}
			},
		)
		done <- outcome{results: results, err: err}
	}()

	select {
	case <-cfStarted:
	case <-time.After(time.Second):
		t.Fatal("cf preparation did not start")
	}
	select {
	case <-cosStarted:
		// COS reached its independent pre-saga boundary while CF was blocked.
	case <-time.After(time.Second):
		t.Fatal("blocked cf observation serialized cos preparation")
	}
	select {
	case result := <-done:
		t.Fatalf("preparation returned before blocked target was released: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCF)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.results) != 2 || result.results[0].target != "cf" || result.results[1].target != "cos" {
		t.Fatalf("target results lost stable order: %+v", result.results)
	}
	if !errors.Is(result.results[0].err, cfFailure) || result.results[1].err != nil || result.results[1].publication.target != "cos" {
		t.Fatalf("one target failure contaminated its sibling: %+v", result.results)
	}
	cfMarker, err := os.ReadFile(filepath.Join(txDir, "target-cf", "marker"))
	if err != nil || string(cfMarker) != "cf" {
		t.Fatalf("cf isolated marker=%q err=%v", cfMarker, err)
	}
	cosMarker, err := os.ReadFile(filepath.Join(txDir, "target-cos", "marker"))
	if err != nil || string(cosMarker) != "cos" {
		t.Fatalf("cos isolated marker=%q err=%v", cosMarker, err)
	}
}

func TestTargetPublicationPipelinesDoNotWaitForSlowSiblingBuild(t *testing.T) {
	txDir := t.TempDir()
	cfStarted := make(chan struct{})
	releaseCF := make(chan struct{})
	cosPersisted := make(chan struct{})
	type outcome struct {
		results []targetPublicationPipelineOutcome
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := runTargetPublicationPipelinesConcurrently(
			context.Background(), []string{"cf", "cos"}, txDir, 1,
			func(_ context.Context, target, targetDir string, workers int) targetPublicationPipelineOutcome {
				if workers != 1 {
					return targetPublicationPipelineOutcome{status: "failed-before-saga", err: fmt.Errorf("target %s workers=%d", target, workers)}
				}
				info, err := os.Lstat(targetDir)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
					return targetPublicationPipelineOutcome{status: "failed-before-saga", err: fmt.Errorf("target %s workspace is unsafe: mode=%v err=%v", target, info, err)}
				}
				switch target {
				case "cf":
					close(cfStarted)
					<-releaseCF
					return targetPublicationPipelineOutcome{status: "failed", err: errors.New("injected slow cf failure")}
				case "cos":
					// This signal models the end of COS build, remote saga, and
					// serialized local ref persistence. It must be reachable while
					// CF is still blocked before its saga.
					close(cosPersisted)
					return targetPublicationPipelineOutcome{status: "published"}
				default:
					return targetPublicationPipelineOutcome{status: "failed", err: fmt.Errorf("unexpected target %s", target)}
				}
			},
		)
		done <- outcome{results: results, err: err}
	}()
	select {
	case <-cfStarted:
	case <-time.After(time.Second):
		t.Fatal("CF pipeline did not start")
	}
	select {
	case <-cosPersisted:
		// Healthy COS reached its durable boundary with a total worker budget
		// of one while CF remained blocked in build/observation.
	case <-time.After(time.Second):
		t.Fatal("slow CF build blocked the complete COS target pipeline")
	}
	select {
	case result := <-done:
		t.Fatalf("aggregate returned before the slow target resolved: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCF)
	result := <-done
	if result.err != nil || len(result.results) != 2 || result.results[0].target != "cf" || result.results[1].target != "cos" ||
		result.results[0].err == nil || result.results[1].err != nil || result.results[1].status != "published" {
		t.Fatalf("independent target pipelines lost ordered outcomes: %+v", result)
	}
}

func TestPublicationUnchangedPreflightsAreConcurrentAndFailureIndependent(t *testing.T) {
	const budget = 1
	cfStarted := make(chan struct{})
	cosStarted := make(chan struct{})
	releaseCF := make(chan struct{})
	cfFailure := errors.New("injected cf control-plane failure")
	type outcome struct {
		results []publicationPreflightResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := runPublicationPreflightsConcurrently(
			context.Background(), []string{"cf", "cos"}, budget,
			func(_ context.Context, target string, workers int) (bool, error) {
				if workers != max(1, budget/2) {
					return false, fmt.Errorf("target %s workers=%d", target, workers)
				}
				switch target {
				case "cf":
					close(cfStarted)
					<-releaseCF
					return false, cfFailure
				case "cos":
					close(cosStarted)
					return true, nil
				default:
					return false, fmt.Errorf("unexpected target %s", target)
				}
			},
		)
		done <- outcome{results: results, err: err}
	}()
	select {
	case <-cfStarted:
	case <-time.After(time.Second):
		t.Fatal("cf unchanged preflight did not start")
	}
	select {
	case <-cosStarted:
	case <-time.After(time.Second):
		t.Fatal("blocked cf control observation serialized cos unchanged preflight")
	}
	select {
	case result := <-done:
		t.Fatalf("preflights returned before blocked target was released: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCF)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.results) != 2 || result.results[0].target != "cf" || result.results[1].target != "cos" {
		t.Fatalf("preflight results lost stable target order: %+v", result.results)
	}
	if !errors.Is(result.results[0].err, cfFailure) || result.results[0].unchanged || result.results[1].err != nil || !result.results[1].unchanged {
		t.Fatalf("one target preflight failure contaminated its sibling: %+v", result.results)
	}
}

func TestPublicationChangedPreflightCancelsSlowSiblingOptimization(t *testing.T) {
	cfStarted := make(chan struct{})
	cfCanceled := make(chan struct{})
	results, err := runPublicationPreflightsConcurrently(
		context.Background(), []string{"cf", "cos"}, 1,
		func(ctx context.Context, target string, workers int) (bool, error) {
			if workers != 1 {
				return false, fmt.Errorf("target %s workers=%d", target, workers)
			}
			switch target {
			case "cf":
				close(cfStarted)
				<-ctx.Done()
				close(cfCanceled)
				return false, ctx.Err()
			case "cos":
				<-cfStarted
				return false, nil
			default:
				return false, fmt.Errorf("unexpected target %s", target)
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cfCanceled:
	default:
		t.Fatal("changed COS preflight did not cancel slow CF optimization")
	}
	if len(results) != 2 || !errors.Is(results[0].err, context.Canceled) || results[0].unchanged || results[1].err != nil || results[1].unchanged {
		t.Fatalf("preflight cancellation outcomes=%+v", results)
	}
}

func TestPublishCLIChangedCOSCommitsWhileCFPipelineIsBlocked(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configBody := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	protocol := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: protocol}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("generation-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "generation-one"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("seed promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "1"); code != ExitOK {
		t.Fatalf("seed publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(input, []byte("generation-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "generation-two"); code != ExitOK {
		t.Fatalf("changed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("changed promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
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
	preflightDir := filepath.Join(root, ".sow", "tmp", "cos-change-preflight")
	if err := os.Mkdir(preflightDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unchanged, err := publicationUnchangedPreflight(t.Context(), cfg, canonical, pool, cfg.Repos, "latest", "cos", preflightDir, commonFlags{workers: 1, chunk: 2})
	if err != nil || unchanged {
		t.Fatalf("changed COS fixture did not require the full pipeline: unchanged=%v err=%v", unchanged, err)
	}

	blocking := &blockingCFCheckpointTransport{
		base: protocol, started: make(chan struct{}), release: make(chan struct{}),
	}
	publishProviderHTTPClient = &http.Client{Transport: blocking}
	type commandResult struct {
		code           int
		stdout, stderr string
	}
	done := make(chan commandResult, 1)
	go func() {
		code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "1")
		done <- commandResult{code: code, stdout: stdout, stderr: stderr}
	}()
	select {
	case <-blocking.started:
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("CF pipeline did not reach the blocked checkpoint read")
	}

	deadline := time.After(publishConcurrencyProgressTimeout)
	for {
		protocol.mutex.Lock()
		cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
		cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
		protocol.mutex.Unlock()
		cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
		cfCheckpoint, cfErr := publish.DecodeCheckpoint(cfBody)
		if cosErr == nil && cosCheckpoint.Generation == 2 {
			if cfErr != nil || cfCheckpoint.Generation != 1 {
				t.Fatalf("blocked CF advanced with COS: cf=%#v err=%v cos=%#v", cfCheckpoint, cfErr, cosCheckpoint)
			}
			break
		}
		select {
		case result := <-done:
			t.Fatalf("publish returned before blocked CF was released: %+v", result)
		case <-deadline:
			t.Fatalf("COS did not reach durable generation 2 while CF remained blocked: body=%s err=%v", cosBody, cosErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(blocking.release)
	select {
	case result := <-done:
		if result.code != ExitOK || strings.Count(result.stdout, "status=published") != 2 {
			t.Fatalf("dual publish after CF release code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
		}
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("dual publish did not finish after CF checkpoint read was released")
	}
}

func TestPublishCLICOSAdvancesBetaLatestStableWhileCFInspectionIsBlocked(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configBody := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: protocol}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("sequence-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "sequence-one"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"promote", "latest", "stable", "--config", configPath, "--repo", "assets"},
		{"publish", "--view", "beta", "--view", "latest", "--view", "stable", "--config", configPath, "--repo", "assets", "--workers", "1"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("seed command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	if err := os.WriteFile(input, []byte("sequence-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "sequence-two"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"promote", "latest", "stable", "--config", configPath, "--repo", "assets"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("changed command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}

	blocking := &blockingCFCheckpointTransport{base: protocol, started: make(chan struct{}), release: make(chan struct{})}
	publishProviderHTTPClient = &http.Client{Transport: blocking}
	type commandResult struct {
		code           int
		stdout, stderr string
	}
	done := make(chan commandResult, 1)
	go func() {
		code, stdout, stderr := run("publish", "--view", "beta", "--view", "latest", "--view", "stable", "--config", configPath, "--repo", "assets", "--workers", "1")
		done <- commandResult{code: code, stdout: stdout, stderr: stderr}
	}()
	select {
	case <-blocking.started:
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("CF sequence did not reach its blocked recovery inspection")
	}

	deadline := time.After(publishConcurrencyProgressTimeout)
	for {
		protocol.mutex.Lock()
		cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
		cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
		protocol.mutex.Unlock()
		cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
		cfCheckpoint, cfErr := publish.DecodeCheckpoint(cfBody)
		if cosErr == nil && cosCheckpoint.Generation == 6 && cosCheckpoint.IntentView == "stable" {
			if cfErr != nil || cfCheckpoint.Generation != 3 || cfCheckpoint.IntentView != "stable" {
				t.Fatalf("blocked CF advanced with COS sequence: cf=%#v err=%v cos=%#v", cfCheckpoint, cfErr, cosCheckpoint)
			}
			break
		}
		select {
		case result := <-done:
			t.Fatalf("multi-view publish returned before blocked CF release: %+v", result)
		case <-deadline:
			t.Fatalf("COS did not reach stable generation 6 while CF inspection was blocked: checkpoint=%s err=%v", cosBody, cosErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(blocking.release)
	select {
	case result := <-done:
		if result.code != ExitOK || strings.Count(result.stdout, "status=published") != 6 {
			t.Fatalf("multi-view publish after CF release code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
		}
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("multi-view publish did not finish after CF release")
	}
}

func TestPublishCLICOSAdvancesAcrossSnapshotsWhileCFInspectionIsBlocked(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configBody := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: protocol}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "snapshot.txt")
	firstSnapshot, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := views.SnapshotID("extra", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshotIDs := []string{firstSnapshot, secondSnapshot}
	if err := os.WriteFile(input, []byte("snapshot-sequence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "sequence"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"promote", "latest", "stable", "--config", configPath, "--repo", "assets"},
		{"promote", "stable", snapshotIDs[0], "--config", configPath, "--repo", "assets"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("snapshot setup command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	// Asset leaves use the fixed logical suite "all", so only all-YYYYMMDD can
	// be captured through the public promote command on a given UTC day. Create
	// a second valid immutable fixture ref directly from the first snapshot;
	// this exercises publication sequencing, not snapshot capture policy.
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	firstRef, _ := state.SnapshotRef(snapshotIDs[0], "assets", "all", "all")
	firstPath, _ := state.SnapshotPath(snapshotIDs[0], "assets", "all", "all")
	firstCommit, exists, err := canonical.Ref(firstRef)
	if err != nil || !exists {
		t.Fatalf("first snapshot ref exists=%t err=%v", exists, err)
	}
	reader, err := canonical.OpenPathAt(firstCommit, firstPath)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	fixtureDir, err := newTransactionDir(cfg.StatePath(), "second-snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fixtureDir)
	stage := filepath.Join(fixtureDir, "second-snapshot.tsv")
	if err := os.WriteFile(stage, body, 0o600); err != nil {
		t.Fatal(err)
	}
	secondPath, _ := state.SnapshotPath(snapshotIDs[1], "assets", "all", "all")
	secondRef, _ := state.SnapshotRef(snapshotIDs[1], "assets", "all", "all")
	if _, changed, err := canonical.Apply(t.Context(), "test-second-snapshot", "create second immutable publication fixture", map[string]string{secondPath: stage}, []state.RefUpdate{{Name: secondRef, Immutable: true}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("create second snapshot changed=%t err=%v", changed, err)
	}

	blocking := &blockingCFCheckpointTransport{base: protocol, started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(blocking.release) })
	publishProviderHTTPClient = &http.Client{Transport: blocking}
	type commandResult struct {
		code           int
		stdout, stderr string
	}
	done := make(chan commandResult, 1)
	go func() {
		code, stdout, stderr := run(
			"publish", "--snapshot", snapshotIDs[0], "--snapshot", snapshotIDs[1],
			"--config", configPath, "--repo", "assets", "--workers", "1",
		)
		done <- commandResult{code: code, stdout: stdout, stderr: stderr}
	}()
	select {
	case <-blocking.started:
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("CF snapshot sequence did not reach its blocked recovery inspection")
	}

	deadline := time.After(publishConcurrencyProgressTimeout)
	for {
		protocol.mutex.Lock()
		cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
		cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
		protocol.mutex.Unlock()
		cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
		if cosErr == nil && cosCheckpoint.Generation == 2 && cosCheckpoint.IntentView == "snapshot" && cosCheckpoint.IntentSnapshot == snapshotIDs[1] {
			if len(cfBody) != 0 {
				t.Fatalf("blocked CF advanced with COS snapshot sequence: cf=%s cos=%#v", cfBody, cosCheckpoint)
			}
			break
		}
		select {
		case result := <-done:
			t.Fatalf("multi-snapshot publish returned before blocked CF release: %+v", result)
		case <-deadline:
			t.Fatalf("COS did not reach second snapshot while CF inspection was blocked: checkpoint=%s err=%v", cosBody, cosErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	releaseOnce.Do(func() { close(blocking.release) })
	select {
	case result := <-done:
		if result.code != ExitOK || strings.Count(result.stdout, "status=published") != 4 {
			t.Fatalf("multi-snapshot publish after CF release code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
		}
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("multi-snapshot publish did not finish after CF release")
	}
}

func TestPublishCLIDefaultCOSAdvancesThroughRetainedSnapshotWhileCFInspectionIsBlocked(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configBody := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: protocol}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "default.txt")
	if err := os.WriteFile(input, []byte("default-target-major\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotID, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "release"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"promote", "latest", "stable", "--config", configPath, "--repo", "assets"},
		{"promote", "stable", snapshotID, "--config", configPath, "--repo", "assets"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("default setup command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}

	blocking := &blockingCFCheckpointTransport{base: protocol, started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(blocking.release) })
	publishProviderHTTPClient = &http.Client{Transport: blocking}
	type commandResult struct {
		code           int
		stdout, stderr string
	}
	done := make(chan commandResult, 1)
	go func() {
		code, stdout, stderr := run("publish", "--config", configPath, "--repo", "assets", "--workers", "1")
		done <- commandResult{code: code, stdout: stdout, stderr: stderr}
	}()
	select {
	case <-blocking.started:
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("CF default sequence did not reach its blocked recovery inspection")
	}

	deadline := time.After(publishConcurrencyProgressTimeout)
	for {
		protocol.mutex.Lock()
		cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
		cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
		protocol.mutex.Unlock()
		cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
		if cosErr == nil && cosCheckpoint.Generation == 4 && cosCheckpoint.IntentView == "snapshot" && cosCheckpoint.IntentSnapshot == snapshotID {
			if len(cfBody) != 0 {
				t.Fatalf("blocked CF advanced with COS default sequence: cf=%s cos=%#v", cfBody, cosCheckpoint)
			}
			break
		}
		select {
		case result := <-done:
			t.Fatalf("default publish returned before blocked CF release: %+v", result)
		case <-deadline:
			t.Fatalf("COS did not reach retained snapshot while CF inspection was blocked: checkpoint=%s err=%v", cosBody, cosErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	releaseOnce.Do(func() { close(blocking.release) })
	select {
	case result := <-done:
		if result.code != ExitOK || strings.Count(result.stdout, "status=published") != 8 {
			t.Fatalf("default publish after CF release code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
		}
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("default publish did not finish after CF release")
	}
}

func TestPublishCLIDefaultRecoversExpiredCFIntentWithoutBlockingCOSViews(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configBody := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret","basic_username":"verifier","basic_password":"verify-secret"}`)
	protocol := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: protocol}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "expired.txt")
	if err := os.WriteFile(input, []byte("expired-snapshot-recovery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "release"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"promote", "latest", "stable", "--config", configPath, "--repo", "assets"},
	} {
		if code, stdout, stderr := run(args...); code != ExitOK {
			t.Fatalf("expired recovery setup command %v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
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
		t.Fatalf("stable fixture ref exists=%t err=%v", exists, err)
	}
	reader, err := canonical.OpenPathAt(stableCommit, stablePath)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	expiredSnapshot := "all-20200101"
	fixtureDir, err := newTransactionDir(cfg.StatePath(), "expired-snapshot-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(fixtureDir, "snapshot.tsv")
	if err := os.WriteFile(stage, body, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotPath, _ := state.SnapshotPath(expiredSnapshot, "assets", "all", "all")
	snapshotRef, _ := state.SnapshotRef(expiredSnapshot, "assets", "all", "all")
	if _, changed, err := canonical.Apply(t.Context(), "test-expired-snapshot", "create expired immutable recovery fixture", map[string]string{snapshotPath: stage}, []state.RefUpdate{{Name: snapshotRef, Immutable: true}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("create expired snapshot changed=%t err=%v", changed, err)
	}
	if err := os.RemoveAll(fixtureDir); err != nil {
		t.Fatal(err)
	}
	retained, err := discoverRecentSnapshots(canonical, timeNowUTC(), cfg.State.SnapshotMaterializationMonths)
	if err != nil || contains(retained, expiredSnapshot) {
		t.Fatalf("expired snapshot unexpectedly retained: retained=%v err=%v", retained, err)
	}

	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	interruptedDir, err := newTransactionDir(cfg.StatePath(), "expired-snapshot-interruption-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 1, chunk: 2}
	prepared, err := preparePublicationSnapshot(t.Context(), cfg, canonical, pool, cfg.Repos, expiredSnapshot, interruptedDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	desiredHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", desiredHead, interruptedDir, values)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	publisher := publish.NewR2CloudflarePublisher(publication.client.r2, publish.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), publish.Hooks{AfterPhase: func(_ publish.TargetName, phase publish.Phase) error {
		if phase == publish.PhaseLocked && !injected {
			injected = true
			return errors.New("injected expired snapshot interruption")
		}
		return nil
	}}).WithWorkers(1)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected expired snapshot interruption") {
		t.Fatalf("expired snapshot interruption err=%v", err)
	}
	if err := os.RemoveAll(interruptedDir); err != nil {
		t.Fatal(err)
	}

	blocking := &blockingCFCheckpointTransport{base: protocol, started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(blocking.release) })
	publishProviderHTTPClient = &http.Client{Transport: blocking}
	type commandResult struct {
		code           int
		stdout, stderr string
	}
	done := make(chan commandResult, 1)
	go func() {
		code, stdout, stderr := run("publish", "--config", configPath, "--repo", "assets", "--workers", "1")
		done <- commandResult{code: code, stdout: stdout, stderr: stderr}
	}()
	select {
	case <-blocking.started:
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("CF expired-snapshot inspection did not block")
	}

	deadline := time.After(publishConcurrencyProgressTimeout)
	for {
		protocol.mutex.Lock()
		cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
		cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
		protocol.mutex.Unlock()
		cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
		if cosErr == nil && cosCheckpoint.Generation == 3 && cosCheckpoint.IntentView == "stable" {
			cfCheckpoint, cfErr := publish.DecodeCheckpoint(cfBody)
			if cfErr != nil || cfCheckpoint.Generation != 1 || cfCheckpoint.IntentView != "snapshot" ||
				cfCheckpoint.IntentSnapshot != expiredSnapshot || cfCheckpoint.Phase != publish.PhaseLocked {
				t.Fatalf("blocked CF checkpoint advanced during COS views: cf=%#v err=%v body=%s cos=%#v", cfCheckpoint, cfErr, cfBody, cosCheckpoint)
			}
			break
		}
		select {
		case result := <-done:
			t.Fatalf("default publish returned before expired CF intent inspection was released: %+v", result)
		case <-deadline:
			t.Fatalf("COS did not reach stable while expired CF intent inspection was blocked: checkpoint=%s err=%v", cosBody, cosErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	releaseOnce.Do(func() { close(blocking.release) })
	select {
	case result := <-done:
		if result.code != ExitOK || strings.Count(result.stdout, "status=published") != 7 ||
			!strings.Contains(result.stdout, "publish materialized snapshot="+expiredSnapshot) ||
			!strings.Contains(result.stdout, "target=cf view=snapshot snapshot="+expiredSnapshot+" generation=1") ||
			strings.Contains(result.stdout, "target=cos view=snapshot snapshot="+expiredSnapshot) {
			t.Fatalf("expired snapshot recovery after CF release code=%d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
		}
	case <-time.After(publishConcurrencyProgressTimeout):
		t.Fatal("default publish did not finish expired CF recovery after release")
	}
	protocol.mutex.Lock()
	cfBody := append([]byte(nil), protocol.objects[publish.CheckpointKey].body...)
	cosBody := append([]byte(nil), protocol.cosObjects[publish.CheckpointKey].body...)
	_, cfSnapshotRoute := protocol.objects[".sow/snapshots/"+expiredSnapshot+".json"]
	_, cosSnapshotRoute := protocol.cosObjects[".sow/snapshots/"+expiredSnapshot+".json"]
	protocol.mutex.Unlock()
	cfCheckpoint, cfErr := publish.DecodeCheckpoint(cfBody)
	cosCheckpoint, cosErr := publish.DecodeCheckpoint(cosBody)
	if cfErr != nil || cfCheckpoint.Generation != 4 || cfCheckpoint.IntentView != "stable" ||
		cosErr != nil || cosCheckpoint.Generation != 3 || cosCheckpoint.IntentView != "stable" ||
		!cfSnapshotRoute || cosSnapshotRoute {
		t.Fatalf("expired recovery final cf=%#v err=%v route=%t cos=%#v err=%v route=%t", cfCheckpoint, cfErr, cfSnapshotRoute, cosCheckpoint, cosErr, cosSnapshotRoute)
	}
}
