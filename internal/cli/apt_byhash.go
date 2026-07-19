package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/state"
)

type aptByHashStage struct {
	CanonicalPath string
	StagedPath    string
	Removed       int
}

// stageAPTByHashGeneration runs only after aptrepo has installed InRelease.
// The canonical ledger is decoded and sealed before a delete plan is applied;
// malformed or missing live state therefore fails closed without collecting a
// single immutable object. The returned file must be committed only after the
// cleanup succeeds.
func stageAPTByHashGeneration(ctx context.Context, canonical *state.Store, targetRoot, namespace, name, repo, suite, txDir string, retain int, generation aptrepo.ByHashGeneration) (aptByHashStage, error) {
	canonicalPath, err := state.APTByHashLedgerPath(namespace, name, repo, suite)
	if err != nil {
		return aptByHashStage{}, err
	}
	scope := namespace + "/" + name
	ledger, err := aptrepo.NewByHashLedger(scope, repo, suite)
	if err != nil {
		return aptByHashStage{}, err
	}
	reader, openErr := canonical.OpenPath(canonicalPath)
	if openErr == nil {
		ledger, err = aptrepo.DecodeByHashLedger(io.LimitReader(reader, 16<<20+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			return aptByHashStage{}, errors.Join(err, closeErr)
		}
		if ledger.Scope != scope || ledger.Repo != repo || ledger.Suite != suite {
			return aptByHashStage{}, fmt.Errorf("APT by-hash ledger identity mismatch at %s", canonicalPath)
		}
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return aptByHashStage{}, openErr
	}
	next, plan, err := ledger.Advance(generation, retain)
	if err != nil {
		return aptByHashStage{}, fmt.Errorf("plan APT by-hash retention for %s/%s/%s: %w", name, repo, suite, err)
	}
	if err := aptrepo.ApplyByHashCleanup(ctx, targetRoot, plan); err != nil {
		return aptByHashStage{}, fmt.Errorf("apply APT by-hash retention for %s/%s/%s: %w", name, repo, suite, err)
	}
	encoded, err := aptrepo.MarshalByHashLedger(next)
	if err != nil {
		return aptByHashStage{}, err
	}
	stage, err := os.CreateTemp(txDir, "apt-by-hash-ledger-*.json")
	if err != nil {
		return aptByHashStage{}, err
	}
	stagePath := stage.Name()
	keep := false
	defer func() {
		if !keep {
			stage.Close()
			os.Remove(stagePath)
		}
	}()
	if err := stage.Chmod(0o600); err != nil {
		return aptByHashStage{}, err
	}
	if _, err := stage.Write(encoded); err != nil {
		return aptByHashStage{}, err
	}
	if err := stage.Sync(); err != nil {
		return aptByHashStage{}, err
	}
	if err := stage.Close(); err != nil {
		return aptByHashStage{}, err
	}
	keep = true
	return aptByHashStage{CanonicalPath: canonicalPath, StagedPath: stagePath, Removed: len(plan.Remove)}, nil
}

func mergeAPTByHashStages(destination map[string]string, stages map[string]string) error {
	for canonicalPath, stagedPath := range stages {
		if existing, duplicate := destination[canonicalPath]; duplicate {
			equal, err := regularFilesEqual(existing, stagedPath)
			if err != nil {
				return err
			}
			if !equal {
				return fmt.Errorf("conflicting APT by-hash ledger stages for %s", canonicalPath)
			}
			continue
		}
		destination[canonicalPath] = stagedPath
	}
	return nil
}

func regularFilesEqual(left, right string) (bool, error) {
	leftData, err := os.ReadFile(left)
	if err != nil {
		return false, err
	}
	rightData, err := os.ReadFile(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftData, rightData), nil
}

func persistAPTByHashStages(ctx context.Context, canonical *state.Store, operation string, staged map[string]string) (string, bool, error) {
	if len(staged) == 0 {
		head, err := canonical.HeadHash()
		return head.String(), false, err
	}
	commit, changed, err := applyCanonicalState(ctx, canonical, operation+"-apt-by-hash", "sow "+operation+": retain APT by-hash generations", staged, nil, state.ApplyOptions{})
	return commit.String(), changed, err
}

func aptByHashStageDir(txDir string) (string, error) {
	directory := filepath.Join(txDir, "apt-by-hash")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	return directory, nil
}
