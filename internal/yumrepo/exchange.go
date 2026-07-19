package yumrepo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DirectoryExchanger is deliberately narrower than rename. Implementations
// must exchange two existing sibling directory entries in one kernel operation.
type DirectoryExchanger interface {
	Probe(parent string) error
	Exchange(first, second string) error
}

// NativeDirectoryExchanger uses renameat2(RENAME_EXCHANGE) on Linux and
// renamex_np(RENAME_SWAP) on macOS. There is no two-rename fallback.
type NativeDirectoryExchanger struct{}

// ActivationPhase identifies the two authorization boundaries around the
// single kernel directory exchange used to activate local repodata.
type ActivationPhase uint8

const (
	ActivationBeforeExchange ActivationPhase = iota + 1
	ActivationAfterExchange
)

func (NativeDirectoryExchanger) Probe(parent string) error {
	parent = filepath.Clean(parent)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: invalid exchange probe parent %q", ErrAtomicUnsupported, parent)
	}
	probe, err := os.MkdirTemp(parent, ".sow-exchange-probe-")
	if err != nil {
		return fmt.Errorf("%w: create probe: %v", ErrAtomicUnsupported, err)
	}
	defer os.RemoveAll(probe)
	first, second := filepath.Join(probe, "first"), filepath.Join(probe, "second")
	if err := os.Mkdir(first, 0o700); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := os.WriteFile(filepath.Join(first, "first.marker"), []byte("first"), 0o600); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := os.WriteFile(filepath.Join(second, "second.marker"), []byte("second"), 0o600); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := syncDirectory(first); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := syncDirectory(second); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := syncDirectory(probe); err != nil {
		return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
	}
	if err := nativeExchange(first, second); err != nil {
		return fmt.Errorf("%w: native exchange probe: %v", ErrAtomicUnsupported, err)
	}
	if _, err := os.Stat(filepath.Join(first, "second.marker")); err != nil {
		return fmt.Errorf("%w: native exchange did not swap first directory: %v", ErrAtomicUnsupported, err)
	}
	if _, err := os.Stat(filepath.Join(second, "first.marker")); err != nil {
		return fmt.Errorf("%w: native exchange did not swap second directory: %v", ErrAtomicUnsupported, err)
	}
	if err := nativeExchange(first, second); err != nil {
		return fmt.Errorf("%w: native exchange probe could not restore: %v", ErrAtomicUnsupported, err)
	}
	return nil
}

func (NativeDirectoryExchanger) Exchange(first, second string) error {
	first, second, err := exchangePaths(first, second)
	if err != nil {
		return err
	}
	if err := nativeExchange(first, second); err != nil {
		if errors.Is(err, errNativeExchangeUnsupported) {
			return fmt.Errorf("%w: %v", ErrAtomicUnsupported, err)
		}
		return fmt.Errorf("yumrepo: atomic directory exchange: %w", err)
	}
	return nil
}

// ActivateLocal atomically swaps a validated staged repodata directory with a
// validated live sibling. expectedRepomdSHA256 is the transaction identity: an
// already-active matching live directory is an idempotent success, while a
// non-matching staged directory is never exchanged. Once the native exchange
// succeeds, this function never swaps back; the old coherent generation stays
// at staged for journal-driven recovery.
func ActivateLocal(ctx context.Context, live, staged string, compression Compression, verifier DetachedVerifier, expectedRepomdSHA256 string, exchanger DirectoryExchanger) error {
	return ActivateLocalGuarded(ctx, live, staged, compression, verifier, expectedRepomdSHA256, exchanger, nil)
}

// ActivateLocalGuarded applies an optional trust/authorization guard directly
// around the native exchange. If the post-exchange guard fails, the function
// exchanges the directories back and verifies that the original live
// generation was restored before returning the guard error.
func ActivateLocalGuarded(ctx context.Context, live, staged string, compression Compression, verifier DetachedVerifier, expectedRepomdSHA256 string, exchanger DirectoryExchanger, guard func(ActivationPhase) error) error {
	if ctx == nil {
		return fmt.Errorf("yumrepo: nil context")
	}
	if exchanger == nil {
		return fmt.Errorf("%w: nil directory exchanger", ErrAtomicUnsupported)
	}
	if !validSHA256(expectedRepomdSHA256) {
		return fmt.Errorf("yumrepo: invalid expected repomd SHA256")
	}
	live, staged, err := exchangePaths(live, staged)
	if err != nil {
		return err
	}
	parent := filepath.Dir(live)
	liveGeneration, err := ValidateDirectory(ctx, live, compression, verifier)
	if err != nil {
		return fmt.Errorf("yumrepo: refuse exchange with invalid live repodata: %w", err)
	}
	if liveGeneration.RepomdSHA256 == expectedRepomdSHA256 {
		if guard != nil {
			if err := guard(ActivationBeforeExchange); err != nil {
				return fmt.Errorf("yumrepo: activation guard: %w", err)
			}
		}
		if err := syncDirectory(live); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			return err
		}
		if guard != nil {
			if err := guard(ActivationAfterExchange); err != nil {
				return fmt.Errorf("yumrepo: activation guard: %w", err)
			}
		}
		return nil
	}
	stagedGeneration, err := ValidateDirectory(ctx, staged, compression, verifier)
	if err != nil {
		return fmt.Errorf("yumrepo: refuse exchange with invalid staged repodata: %w", err)
	}
	if stagedGeneration.RepomdSHA256 != expectedRepomdSHA256 {
		return fmt.Errorf("yumrepo: staged repomd SHA256 %s does not match expected %s", stagedGeneration.RepomdSHA256, expectedRepomdSHA256)
	}
	if guard != nil {
		if err := guard(ActivationBeforeExchange); err != nil {
			return fmt.Errorf("yumrepo: pre-exchange guard: %w", err)
		}
	}
	if err := exchanger.Probe(parent); err != nil {
		return err
	}
	if err := syncDirectory(live); err != nil {
		return err
	}
	if err := syncDirectory(staged); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := exchanger.Exchange(live, staged); err != nil {
		return err
	}
	activationErr := syncDirectory(parent)
	// Cancellation after the exchange cannot authorize rolling committed local
	// state back. Validate with a non-cancelable context and leave the old
	// generation at staged for explicit recovery if storage reports an error.
	activated, err := ValidateDirectory(context.WithoutCancel(ctx), live, compression, verifier)
	if err != nil {
		activationErr = errors.Join(activationErr, fmt.Errorf("yumrepo: exchange completed but active repodata validation failed: %w", err))
	} else if activated.RepomdSHA256 != expectedRepomdSHA256 {
		activationErr = errors.Join(activationErr, fmt.Errorf("yumrepo: exchange completed with unexpected active repomd SHA256 %s", activated.RepomdSHA256))
	}
	if guard != nil {
		if guardErr := guard(ActivationAfterExchange); guardErr != nil {
			rollbackErr := exchanger.Exchange(live, staged)
			if rollbackErr == nil {
				rollbackErr = syncDirectory(parent)
			}
			if rollbackErr == nil {
				restored, validateErr := ValidateDirectory(context.WithoutCancel(ctx), live, compression, verifier)
				if validateErr != nil {
					rollbackErr = validateErr
				} else if restored.RepomdSHA256 != liveGeneration.RepomdSHA256 {
					rollbackErr = fmt.Errorf("yumrepo: rollback restored unexpected live repomd SHA256 %s", restored.RepomdSHA256)
				}
			}
			if rollbackErr != nil {
				return errors.Join(activationErr, fmt.Errorf("yumrepo: post-exchange guard: %w", guardErr), fmt.Errorf("yumrepo: trust rollback failed: %w", rollbackErr))
			}
			return errors.Join(activationErr, fmt.Errorf("yumrepo: post-exchange guard: %w", guardErr))
		}
	}
	return activationErr
}

// ActivateInitialLocalGuarded installs the first validated repodata generation
// with a sibling rename. A post-install guard failure renames it back out of
// the live coordinate and verifies that no live generation remains.
func ActivateInitialLocalGuarded(ctx context.Context, live, staged string, compression Compression, verifier DetachedVerifier, expectedRepomdSHA256 string, guard func(ActivationPhase) error) error {
	if ctx == nil {
		return errors.New("yumrepo: nil context")
	}
	if !validSHA256(expectedRepomdSHA256) {
		return errors.New("yumrepo: invalid expected repomd SHA256")
	}
	liveAbs, err := filepath.Abs(live)
	if err != nil {
		return err
	}
	stagedAbs, err := filepath.Abs(staged)
	if err != nil {
		return err
	}
	liveAbs, stagedAbs = filepath.Clean(liveAbs), filepath.Clean(stagedAbs)
	if liveAbs == stagedAbs || filepath.Dir(liveAbs) != filepath.Dir(stagedAbs) {
		return errors.New("yumrepo: initial activation requires distinct sibling directories")
	}
	if _, err := os.Lstat(liveAbs); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("yumrepo: initial live repodata coordinate already exists"))
	}
	stagedInfo, err := os.Lstat(stagedAbs)
	if err != nil || !stagedInfo.IsDir() || stagedInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("yumrepo: staged repodata is not a real directory"))
	}
	stagedGeneration, err := ValidateDirectory(ctx, stagedAbs, compression, verifier)
	if err != nil {
		return fmt.Errorf("yumrepo: refuse initial activation of invalid staged repodata: %w", err)
	}
	if stagedGeneration.RepomdSHA256 != expectedRepomdSHA256 {
		return fmt.Errorf("yumrepo: staged repomd SHA256 %s does not match expected %s", stagedGeneration.RepomdSHA256, expectedRepomdSHA256)
	}
	if guard != nil {
		if err := guard(ActivationBeforeExchange); err != nil {
			return fmt.Errorf("yumrepo: pre-install guard: %w", err)
		}
	}
	parent := filepath.Dir(liveAbs)
	if err := syncDirectory(stagedAbs); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := installImmutable(stagedAbs, liveAbs); err != nil {
		return fmt.Errorf("yumrepo: install initial local repodata: %w", err)
	}
	activationErr := syncDirectory(parent)
	activated, err := ValidateDirectory(context.WithoutCancel(ctx), liveAbs, compression, verifier)
	if err != nil || activated.RepomdSHA256 != expectedRepomdSHA256 {
		activationErr = errors.Join(activationErr, err, errors.New("yumrepo: initial activation identity mismatch"))
	}
	if guard != nil {
		if guardErr := guard(ActivationAfterExchange); guardErr != nil {
			rollbackErr := installImmutable(liveAbs, stagedAbs)
			if rollbackErr == nil {
				rollbackErr = syncDirectory(parent)
			}
			if rollbackErr == nil {
				if _, statErr := os.Lstat(liveAbs); !errors.Is(statErr, os.ErrNotExist) {
					rollbackErr = errors.Join(statErr, errors.New("yumrepo: initial rollback left live repodata present"))
				}
			}
			if rollbackErr != nil {
				return errors.Join(activationErr, fmt.Errorf("yumrepo: post-install guard: %w", guardErr), fmt.Errorf("yumrepo: trust rollback failed: %w", rollbackErr))
			}
			return errors.Join(activationErr, fmt.Errorf("yumrepo: post-install guard: %w", guardErr))
		}
	}
	return activationErr
}

func exchangePaths(first, second string) (string, string, error) {
	firstAbs, err := filepath.Abs(first)
	if err != nil {
		return "", "", err
	}
	secondAbs, err := filepath.Abs(second)
	if err != nil {
		return "", "", err
	}
	firstAbs, secondAbs = filepath.Clean(firstAbs), filepath.Clean(secondAbs)
	if firstAbs == secondAbs || filepath.Dir(firstAbs) != filepath.Dir(secondAbs) {
		return "", "", fmt.Errorf("yumrepo: atomic exchange requires two distinct sibling directories")
	}
	for _, item := range []string{firstAbs, secondAbs} {
		info, err := os.Lstat(item)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("yumrepo: exchange path %q is not a real directory", item)
		}
	}
	return firstAbs, secondAbs, nil
}
