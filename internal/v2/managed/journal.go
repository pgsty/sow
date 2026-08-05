package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/pgsty/sow/internal/v2/config"
)

const (
	workspaceJournalVersion  = 1
	maxWorkspaceJournalBytes = 32 << 20
)

var lowercaseSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var decimalOperationID = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)

func validStoredOperationID(id string) bool {
	// Hex IDs are accepted only so an interrupted pre-contract development
	// workspace remains recoverable. Newly generated and public IDs are decimal.
	return decimalOperationID.MatchString(id) || lowercaseSHA256.MatchString(id)
}

type workspaceJournal struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Repository   string `json:"repository"`
	OldConfigSHA string `json:"old_config_sha256"`
	OldConfig    []byte `json:"old_config"`
	NewConfigSHA string `json:"new_config_sha256"`
	NewConfig    []byte `json:"new_config"`
	Phase        string `json:"phase"`
}

func workspaceJournalPath(root string) string {
	return filepath.Join(root, ".sow", "workspace-ops", "active.json")
}

func persistWorkspaceJournal(root string, journal workspaceJournal) error {
	if err := validateWorkspaceJournal(journal); err != nil {
		return err
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := validateWorkspaceJournalWireSize(data); err != nil {
		return err
	}
	return writeAtomic(workspaceJournalPath(root), data, 0o600)
}

func validateWorkspaceJournalWireSize(data []byte) error {
	if len(data) > maxWorkspaceJournalBytes {
		return fmt.Errorf("%w: workspace journal exceeds %d bytes", ErrRejected, maxWorkspaceJournalBytes)
	}
	return nil
}

func loadWorkspaceJournal(root string) (*workspaceJournal, error) {
	data, err := readRootedPrivateRegular(filepath.Join(root, ".sow", "workspace-ops"), "active.json", maxWorkspaceJournalBytes, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: workspace journal is missing, unsafe, empty, oversized, or unstable", ErrIntegrity)
	}
	var journal workspaceJournal
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&journal); err != nil {
		return nil, fmt.Errorf("%w: decode workspace journal: %v", ErrIntegrity, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%w: workspace journal has trailing content", ErrIntegrity)
	}
	if err := validateWorkspaceJournal(journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

// inspectWorkspaceJournal is the read-only half of workspace recovery. It
// authenticates the closed journal and proves that the current config is one
// of the journal's durable decision states, but never repairs or clears it.
func inspectWorkspaceJournal(root string) (*workspaceJournal, error) {
	journal, err := loadWorkspaceJournal(root)
	if err != nil || journal == nil {
		return journal, err
	}
	configPath := filepath.Join(root, config.ConfigFilename)
	info, statErr := os.Lstat(configPath)
	if errors.Is(statErr, os.ErrNotExist) {
		if journal.Kind == "workspace.init" && journal.Phase == "planned" {
			return journal, nil
		}
		return nil, fmt.Errorf("%w: workspace journal config is missing", ErrIntegrity)
	}
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: workspace journal config path is unsafe", ErrIntegrity)
	}
	currentSHA, err := config.FileSHA(configPath)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect workspace journal config: %v", ErrIntegrity, err)
	}
	if journal.Kind == "workspace.init" {
		if currentSHA != journal.NewConfigSHA {
			return nil, fmt.Errorf("%w: workspace initialization journal does not match config", ErrIntegrity)
		}
		return journal, nil
	}
	if currentSHA != journal.OldConfigSHA && currentSHA != journal.NewConfigSHA {
		return nil, fmt.Errorf("%w: workspace journal config matches neither decision state", ErrIntegrity)
	}
	return journal, nil
}

func validateWorkspaceJournal(journal workspaceJournal) error {
	validKind := journal.Kind == "workspace.init" || journal.Kind == "repo.init" || journal.Kind == "repo.new" || journal.Kind == "repo.rm"
	validPhase := journal.Phase == "planned" || journal.Phase == "applied"
	if journal.Version != workspaceJournalVersion || !validStoredOperationID(journal.ID) || !validKind || !validPhase || !lowercaseSHA256.MatchString(journal.NewConfigSHA) || bytesSHA(journal.NewConfig) != journal.NewConfigSHA {
		return fmt.Errorf("%w: invalid workspace journal", ErrIntegrity)
	}
	newConfig, err := config.Parse(journal.NewConfig)
	if err != nil {
		return fmt.Errorf("%w: invalid new journal config: %v", ErrIntegrity, err)
	}
	if journal.Kind == "workspace.init" {
		defaults, err := config.Marshal(config.Default())
		if err != nil || journal.Repository != "" || journal.OldConfigSHA != "" || len(journal.OldConfig) != 0 || !bytes.Equal(journal.NewConfig, defaults) {
			return fmt.Errorf("%w: workspace.init journal is not bound to the default config", ErrIntegrity)
		}
		return nil
	}
	if !lowercaseSHA256.MatchString(journal.OldConfigSHA) || config.ValidateName(journal.Repository) != nil || bytesSHA(journal.OldConfig) != journal.OldConfigSHA {
		return fmt.Errorf("%w: invalid repository workspace journal", ErrIntegrity)
	}
	oldConfig, err := config.Parse(journal.OldConfig)
	if err != nil {
		return fmt.Errorf("%w: invalid old journal config: %v", ErrIntegrity, err)
	}
	_, oldRepositoryPresent := oldConfig.Repositories[journal.Repository]
	_, repositoryPresent := newConfig.Repositories[journal.Repository]
	switch journal.Kind {
	case "repo.init":
		if !oldRepositoryPresent || !repositoryPresent || journal.OldConfigSHA != journal.NewConfigSHA {
			return fmt.Errorf("%w: repo.init journal is not bound to an unchanged config containing %q", ErrIntegrity, journal.Repository)
		}
	case "repo.new":
		if oldRepositoryPresent || !repositoryPresent || journal.OldConfigSHA == journal.NewConfigSHA {
			return fmt.Errorf("%w: repo.new journal config does not add %q", ErrIntegrity, journal.Repository)
		}
	case "repo.rm":
		if !oldRepositoryPresent || repositoryPresent || journal.OldConfigSHA == journal.NewConfigSHA {
			return fmt.Errorf("%w: repo.rm journal config does not remove %q", ErrIntegrity, journal.Repository)
		}
	}
	return nil
}

func clearWorkspaceJournal(root string) error {
	return removeRootedRegular(filepath.Join(root, ".sow", "workspace-ops"), "active.json", -1)
}

func recoverWorkspaceOperation(ctx context.Context, root string) error {
	if err := validateWorkspaceOpsLayout(root); err != nil {
		return err
	}
	journal, err := loadWorkspaceJournal(root)
	if err != nil || journal == nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	configPath := filepath.Join(root, config.ConfigFilename)
	currentSHA := ""
	configExists := false
	if info, statErr := os.Lstat(configPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: sow.yml is not a regular file during recovery", ErrIntegrity)
		}
		configExists = true
		currentSHA, err = config.FileSHA(configPath)
		if err != nil {
			return fmt.Errorf("%w: inspect config during recovery: %v", ErrIntegrity, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("%w: inspect config during recovery: %v", ErrIntegrity, statErr)
	}
	if journal.Kind == "workspace.init" {
		if !configExists && journal.Phase == "planned" {
			return clearWorkspaceJournal(root)
		}
		if !configExists || currentSHA != journal.NewConfigSHA {
			return fmt.Errorf("%w: config does not match workspace initialization evidence", ErrIntegrity)
		}
		return clearWorkspaceJournal(root)
	}
	if currentSHA == journal.OldConfigSHA && journal.Kind != "repo.init" {
		// No commit decision: roll back the operation. The invoking command may
		// then plan the requested change again from current state.
		return clearWorkspaceJournal(root)
	}
	if currentSHA == journal.NewConfigSHA {
		// Config rename is the forward commit decision.
	} else {
		return fmt.Errorf("%w: config hash matches neither side of workspace operation", ErrIntegrity)
	}
	switch journal.Kind {
	case "repo.init", "repo.new":
		if _, err := ensureRepositoryShell(root, journal.Repository); err != nil {
			return err
		}
	case "repo.rm":
		lockPath := filepath.Join(root, ".sow", "repo-locks", journal.Repository+".lock")
		var repoLock *fileLock
		if _, statErr := os.Lstat(lockPath); statErr == nil {
			repoLock, err = acquireFileLock(ctx, lockPath, 0, false)
			if err != nil {
				return err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		} else {
			detached := filepath.Join(root, ".sow", "workspace-ops", "recovery-"+journal.ID, "lock")
			if info, detachedErr := os.Lstat(detached); detachedErr == nil {
				if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("%w: detached repository lock is unsafe", ErrIntegrity)
				}
			} else if !errors.Is(detachedErr, os.ErrNotExist) {
				return detachedErr
			} else if repositoryRemovalPathsRemain(root, journal.Repository) {
				return fmt.Errorf("%w: repository lock disappeared before removal completed", ErrIntegrity)
			}
		}
		removeErr := removeRepositoryOwnedPaths(root, journal.Repository, journal.ID)
		if repoLock != nil {
			removeErr = errors.Join(removeErr, repoLock.Close())
		}
		if removeErr != nil {
			return removeErr
		}
	}
	return clearWorkspaceJournal(root)
}

func repositoryRemovalPathsRemain(root, name string) bool {
	for _, candidate := range []string{
		filepath.Join(root, name),
		filepath.Join(root, ".sow", name),
		filepath.Join(root, ".sow", name+".db"),
		filepath.Join(root, ".sow", name+".db-wal"),
		filepath.Join(root, ".sow", name+".db-shm"),
		filepath.Join(root, ".sow", name+".db-journal"),
	} {
		if _, err := os.Lstat(candidate); err == nil || !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}
