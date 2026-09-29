package v2cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/managed"
	"github.com/pgsty/sow/internal/v2/plain"
	"golang.org/x/sys/unix"
)

func TestCancellationClassificationPreservesLockTimeout(t *testing.T) {
	for _, err := range []error{
		context.Canceled,
		fmt.Errorf("%w: %w", managed.ErrRejected, context.Canceled),
		fmt.Errorf("%w: %w", managed.ErrLockUnavailable, context.Canceled),
	} {
		classified := classifyManagedError("add", markCommandInterrupted(cancelledContext(), err))
		if ExitCode(classified) != ExitInterrupted || errorClass(ExitCode(classified)) != "interrupted" {
			t.Fatalf("cancelled operation classified as %d: %v", ExitCode(classified), classified)
		}
		if !strings.HasPrefix(classified.Error(), "context canceled") {
			t.Fatalf("interrupted diagnostic lost its cancellation cause: %v", classified)
		}
	}
	// An internal cancellation (for example an R2 upload progress watchdog) is
	// not a user interrupt while the command context itself is still live.
	internal := fmt.Errorf("upload: %w", errors.Join(context.Canceled, errors.New("R2 upload made no progress before its idle deadline")))
	if got := ExitCode(classifyManagedError("publish", markCommandInterrupted(context.Background(), internal))); got == ExitInterrupted {
		t.Fatalf("internal cancellation classified as interrupted")
	}
	err := fmt.Errorf("%w: %w", managed.ErrLockUnavailable, context.DeadlineExceeded)
	if got := ExitCode(classifyManagedError("add", err)); got != ExitLock {
		t.Fatalf("lock timeout=%d, want %d", got, ExitLock)
	}
	if got := ExitCode(classifyPlainError(markCommandInterrupted(cancelledContext(), &plain.Error{Kind: plain.KindLock, Op: "lock", Err: context.Canceled}))); got != ExitInterrupted {
		t.Fatalf("plain cancellation=%d", got)
	}
}

func TestInterruptedMessageDoesNotRepeatCancellation(t *testing.T) {
	err := markCommandInterrupted(cancelledContext(), context.Canceled)
	if ExitCode(err) != ExitInterrupted || err.Error() != "context canceled" {
		t.Fatalf("interrupted error=%q code=%d", err, ExitCode(err))
	}
}

func TestMainCancellationWhileWaitingForLock(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root}, "initialized")
	lock, err := os.OpenFile(filepath.Join(root, ".sow", "workspace.lock"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	var stdout, stderr bytes.Buffer
	code := MainContext(ctx, []string{"repo", "new", "cancelled", "-C", root, "--json"}, &stdout, &stderr)
	if code != ExitInterrupted || !strings.Contains(stdout.String(), `"class":"interrupted"`) || !strings.Contains(stdout.String(), `"result":null`) || stderr.Len() == 0 {
		t.Fatalf("cancellation code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "cancelled.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled lock waiter created repository state: %v", err)
	}
}

func TestExecuteCreateCancellationKeepsResult(t *testing.T) {
	inv, err := Parse([]string{"create", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := ExecuteCreate(ctx, inv, &stdout, &stderr, func(context.Context, plain.Options) (plain.Result, error) {
		cancel()
		return plain.Result{Dir: "/tmp/fixture", RPM: 2}, errors.New("signer process terminated")
	})
	if code != ExitInterrupted || !strings.Contains(stdout.String(), `"class":"interrupted"`) || !strings.Contains(stdout.String(), `"rpm":2`) {
		t.Fatalf("cancelled create code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
	}
}

func TestMainAddDoesNotPrintEmptyPreflightStatistics(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root}, "initialized")
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root}, "created repo")
	assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo"}, "created el9")
	inputs := t.TempDir()
	valid := decodeCLIFixture(t, filepath.Join("..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
	configPath := filepath.Join(root, config.ConfigFilename)
	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "fill", Key: "env://SOW_CLI_MISSING_SIGNING_KEY"}
	cfg.Repositories["repo"] = repo
	t.Setenv("SOW_CLI_MISSING_SIGNING_KEY", "")
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"add", valid, "-C", root, "-r", "repo", "-d", "el9"}
	stdout, stderr, code := runCLI(args)
	if code == ExitOK || stdout != "" || stderr == "" {
		t.Fatalf("preflight code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI(append(args, "--json"))
	if code == ExitOK || !strings.Contains(stdout, `"result":null`) || stderr == "" {
		t.Fatalf("preflight JSON code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(inputs, "invalid.rpm")
	if err := os.WriteFile(invalid, []byte("not an RPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	args[1] = invalid
	stdout, stderr, code = runCLI(args)
	if code != ExitRejected || !strings.Contains(stdout, "accepted=0 failed=1") || !strings.Contains(stdout, "status=failed") || stderr == "" {
		t.Fatalf("per-item failure code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
