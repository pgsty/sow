package v2cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/managed"
	"github.com/pgsty/sow/internal/v2/state"
)

// Main is the active SOW V2 command entry point. It intentionally dispatches
// only the closed P0-P3 command tree accepted by Parse.
func Main(args []string, stdout, stderr io.Writer) int {
	return MainContext(context.Background(), args, stdout, stderr)
}

// MainContext is Main with a caller-owned cancellation context for tests and
// embedders. Command diagnostics always go to stderr; --json data always goes
// to stdout, including failure envelopes.
func MainContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	inv, err := Parse(args)
	if err != nil {
		command, jsonOutput := failureInvocationContext(args)
		return writeFailure(command, jsonOutput, err, nil, nil, nil, stdout, stderr)
	}
	if inv.Help || inv.Command == "help" {
		body := Help(inv)
		if body == "" {
			err := usageError("unknown help topic %q", strings.Join(inv.Positionals, " "))
			return writeFailure("help", false, err, nil, nil, nil, stdout, stderr)
		}
		return writeHuman(stdout, stderr, body)
	}
	if inv.Version {
		return writeHuman(stdout, stderr, VersionString()+"\n")
	}
	if inv.Command == "create" {
		return ExecuteCreate(ctx, inv, stdout, stderr, nil)
	}
	if invocationCommand(inv) == "log export" {
		return executeLogExport(ctx, inv, stdout, stderr)
	}

	output, err := executeManaged(ctx, inv)
	command := invocationCommand(inv)
	if err != nil {
		classified := classifyManagedError(command, err)
		if command == "init" {
			if result, ok := output.result.(managed.InitResult); ok && result.HasCommittedChanges() {
				classified = WithExitCode(ExitPartial, classified)
			}
		}
		if ExitCode(classified) == ExitPartial && !inv.Global.JSON && output.human != "" {
			if code := writeHuman(stdout, stderr, output.human); code != ExitOK {
				return code
			}
		}
		if command == "check" && !inv.Global.JSON && output.human != "" {
			if code := writeHuman(stdout, stderr, output.human); code != ExitOK {
				return code
			}
		}
		return writeFailure(command, inv.Global.JSON, classified, output.repository, output.operation, output.result, stdout, stderr)
	}
	if inv.Global.JSON {
		if err := WriteJSON(stdout, NewEnvelope(command, output.repository, output.operation, output.result)); err != nil {
			fmt.Fprintln(stderr, err)
			return ExitRuntime
		}
		return ExitOK
	}
	return writeHuman(stdout, stderr, output.human)
}

type managedOutput struct {
	repository any
	operation  any
	result     any
	human      string
}

var initWorkspace = managed.Init

func executeManaged(ctx context.Context, inv Invocation) (managedOutput, error) {
	workspaceOptions := managed.WorkspaceOptions{Workdir: inv.Global.Workdir}
	lockOptions := managed.LockOptions{Timeout: inv.Global.Timeout, NoWait: inv.Global.NoWait}
	switch invocationCommand(inv) {
	case "init":
		directory := "."
		if len(inv.Positionals) == 1 {
			directory = inv.Positionals[0]
		}
		if err := preflightInitConfig(directory); err != nil {
			return managedOutput{}, err
		}
		result, err := initWorkspace(ctx, managed.InitOptions{Dir: directory})
		return managedOutput{result: result, human: fmt.Sprintf(
			"initialized %s: config_created=%t repositories_initialized=%d dists_initialized=%d\n",
			result.Workspace, result.ConfigCreated, result.RepositoriesInitialized, result.DistsInitialized,
		)}, err

	case "config check":
		if _, _, err := loadWorkspace(workspaceOptions); err != nil {
			return managedOutput{}, err
		}
		result, err := managed.CheckConfig(ctx, workspaceOptions)
		return managedOutput{result: result, human: fmt.Sprintf(
			"configuration valid: %s repositories=%d dists=%d\n",
			result.Workspace, result.Repositories, result.Dists,
		)}, err

	case "config show":
		view, repository, err := showConfig(ctx, inv, workspaceOptions)
		if err != nil {
			return managedOutput{repository: nullableString(repository)}, err
		}
		data, err := config.MarshalEffective(view)
		return managedOutput{repository: nullableString(repository), result: view, human: string(data)}, err

	case "repo ls":
		if _, _, err := loadWorkspace(workspaceOptions); err != nil {
			return managedOutput{}, err
		}
		result, err := managed.ListRepositories(ctx, workspaceOptions)
		return managedOutput{result: map[string]any{"repositories": result}, human: repositoriesHuman(result)}, err

	case "repo new":
		name := inv.Positionals[0]
		if _, _, err := loadWorkspace(workspaceOptions); err != nil {
			return managedOutput{repository: name}, err
		}
		result, err := managed.NewRepository(ctx, managed.RepositoryNewOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Name: name,
		})
		return managedOutput{repository: name, result: result, human: repositoryHuman("created", result)}, err

	case "repo show":
		name := inv.Global.Repo
		if len(inv.Positionals) == 1 {
			if inv.Global.Repo != "" && inv.Global.Repo != inv.Positionals[0] {
				return managedOutput{}, Errorf(ErrRejected,
					"repo show NAME %q and --repo %q select different repositories",
					inv.Positionals[0], inv.Global.Repo)
			}
			name = inv.Positionals[0]
		}
		ws, cfg, err := loadWorkspace(workspaceOptions)
		if err != nil {
			return managedOutput{repository: nullableString(name)}, err
		}
		if name == "" {
			name, err = selectedRepository(ws, cfg, "")
			if err != nil {
				return managedOutput{}, err
			}
		}
		result, err := managed.ShowRepository(ctx, managed.RepositoryShowOptions{
			WorkspaceOptions: workspaceOptions, Repository: name, Name: name,
		})
		return managedOutput{repository: name, result: result, human: repositoryShowHuman(result)}, err

	case "repo migrate":
		name := inv.Global.Repo
		if len(inv.Positionals) == 1 {
			if name != "" && name != inv.Positionals[0] {
				return managedOutput{}, Errorf(ErrRejected,
					"repo migrate NAME %q and --repo %q select different repositories",
					inv.Positionals[0], name)
			}
			name = inv.Positionals[0]
		}
		migrationOptions := managed.RepositoryMigrationOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: name, Jobs: inv.Jobs,
		}
		if inv.Abort {
			result, err := managed.AbandonRepositoryMigration(ctx, migrationOptions)
			return managedOutput{repository: nullableString(result.Repository), result: result, human: fmt.Sprintf(
				"abandoned repository migration %s: phase=%s complete=%t\n", result.Repository, result.Phase, result.Complete,
			)}, err
		}
		result, err := managed.MigrateRepository(ctx, migrationOptions)
		return managedOutput{repository: nullableString(result.Repository), result: result, human: fmt.Sprintf(
			"migrated repository %s: %s -> %s generation=%s phase=%s complete=%t\n",
			result.Repository, result.FromLayout, result.ToLayout, result.Generation, result.Phase, result.Complete,
		)}, err

	case "repo rm":
		name := inv.Positionals[0]
		if _, _, err := loadWorkspace(workspaceOptions); err != nil {
			return managedOutput{repository: name}, err
		}
		result, err := managed.RemoveRepositoryResult(ctx, managed.RepositoryRemoveOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Name: name, Force: inv.Force,
		})
		human := fmt.Sprintf("removed repository %s\n", name)
		if result.Noop {
			human = fmt.Sprintf("repository %s already absent (noop)\n", name)
		}
		return managedOutput{repository: name, result: map[string]any{"name": name, "removed": result.Removed, "noop": result.Noop}, human: human}, err

	case "dist ls", "dist new", "dist show", "dist rm":
		ws, cfg, err := loadWorkspace(workspaceOptions)
		if err != nil {
			return managedOutput{repository: nullableString(inv.Global.Repo)}, err
		}
		repository, err := selectedRepository(ws, cfg, inv.Global.Repo)
		if err != nil {
			return managedOutput{repository: nullableString(inv.Global.Repo)}, err
		}
		switch invocationCommand(inv) {
		case "dist ls":
			result, err := managed.ListDists(ctx, managed.DistListOptions{WorkspaceOptions: workspaceOptions, Repository: repository})
			return managedOutput{repository: repository, result: map[string]any{"dists": result}, human: distsHuman(result)}, err
		case "dist new":
			result, err := managed.NewDist(ctx, managed.DistNewOptions{
				WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: repository,
				Name: inv.Positionals[0], Format: inv.Format,
			})
			return managedOutput{repository: repository, result: result, human: distHuman("created", result)}, err
		case "dist show":
			result, err := managed.ShowDist(ctx, managed.DistShowOptions{
				WorkspaceOptions: workspaceOptions, Repository: repository, Name: inv.Positionals[0],
			})
			return managedOutput{repository: repository, result: result, human: distShowHuman(result)}, err
		default:
			name := inv.Positionals[0]
			result, err := managed.RemoveDistResult(ctx, managed.DistRemoveOptions{
				WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: repository,
				Name: name, Force: inv.Force,
			})
			human := fmt.Sprintf("removed dist %s from %s\n", name, repository)
			if result.Noop {
				human = fmt.Sprintf("dist %s already absent from %s (noop)\n", name, repository)
			}
			return managedOutput{repository: repository, result: map[string]any{"name": name, "removed": result.Removed, "noop": result.Noop}, human: human}, err
		}

	case "add":
		result, err := managed.Add(ctx, managed.AddOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo,
			Dists: inv.Global.Dists, Paths: inv.Positionals, Recursive: inv.Recursive, Skip: inv.Skip, Jobs: inv.Jobs,
		})
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Operation), result: result, human: mutationHuman("add", result)}, err

	case "rm":
		result, err := managed.Remove(ctx, managed.RemoveOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo,
			Dists: inv.Global.Dists, Packages: inv.Positionals, Check: inv.Check, Skip: inv.Skip, Jobs: inv.Jobs,
		})
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Operation), result: result, human: humanJSON(result) + "\n"}, err

	case "ls":
		result, err := managed.ListPackages(ctx, managed.PackageListOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: packagesHuman(result)}, err

	case "show":
		result, err := managed.ShowPackage(ctx, managed.PackageShowOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists, Reference: inv.Positionals[0]})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: humanJSON(result) + "\n"}, err

	case "where":
		result, err := managed.WherePackage(ctx, managed.PackageWhereOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists, Reference: inv.Positionals[0]})
		return managedOutput{result: result, human: humanJSON(result) + "\n"}, err

	case "status":
		result, err := managed.Status(ctx, managed.StatusOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: statusHuman(result)}, err

	case "build":
		result, err := managed.Build(ctx, managed.BuildOptions{WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists, Jobs: inv.Jobs})
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Operation), result: result, human: humanJSON(result) + "\n"}, err

	case "check":
		result, err := managed.Check(ctx, managed.CheckOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists, Jobs: inv.Jobs})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: checkHuman(result)}, err

	case "changes":
		var base *state.GenerationID
		if len(inv.Positionals) == 1 {
			parsed, parseErr := parseGenerationIDArgument(inv.Positionals[0])
			if parseErr != nil {
				return managedOutput{}, parseErr
			}
			base = &parsed
		}
		result, err := managed.Changes(ctx, managed.ChangesOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Base: base})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: changesHuman(result)}, err

	case "publish":
		if inv.Abort {
			result, err := managed.AbandonPublication(ctx, managed.PublicationAbandonOptions{
				WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Target: inv.Positionals[0],
			})
			return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Attempt), result: result, human: fmt.Sprintf(
				"abandoned publication %s for %s: retained-evidence objects=%d\n", result.Attempt, result.Target, result.Objects,
			)}, err
		}
		result, err := managed.Publish(ctx, managed.PublishOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Target: inv.Positionals[0],
		})
		human := fmt.Sprintf("published %s generation=%s to %s (%s): phase=%s objects=%d\n", result.Repository, result.Generation, result.Target, result.Provider, result.Phase, result.Objects)
		if result.Noop {
			human = fmt.Sprintf("publication %s generation=%s to %s is already current (noop)\n", result.Repository, result.Generation, result.Target)
		}
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Attempt), result: result, human: human}, err

	case "retain add", "retain rm":
		generation, parseErr := parseGenerationIDArgument(inv.Positionals[0])
		if parseErr != nil || generation == 0 {
			return managedOutput{}, usageError("retained generation must be a decimal integer greater than zero")
		}
		if invocationCommand(inv) == "retain add" {
			result, err := managed.RetainAdd(ctx, managed.RetainAddOptions{
				WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo, Generation: generation,
			})
			return managedOutput{repository: nullableString(result.Repository), result: result, human: fmt.Sprintf(
				"retained generation %s: %s\n", result.Record.Generation, result.Path,
			)}, err
		}
		result, err := managed.RetainRemove(ctx, managed.RetainRemoveOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo, Generation: generation,
		})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: fmt.Sprintf(
			"removed retained generation %s\n", generation,
		)}, err

	case "retain ls":
		result, err := managed.RetainList(ctx, managed.RetainListOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: retainedHuman(result.Generations)}, err

	case "gc":
		if len(inv.Positionals) == 1 {
			result, err := managed.TargetGC(ctx, managed.TargetGCOptions{
				WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Target: inv.Positionals[0],
			})
			human := fmt.Sprintf("target gc %s/%s (%s): phase=%s candidates=%d deleted=%d retained=%d pending=%d\n", result.Repository, result.Target, result.Provider, result.Phase, result.Candidates, result.DeletedObjects, result.RetainedObjects, result.PendingGrace)
			if result.Noop {
				human = fmt.Sprintf("target gc %s/%s: no due maintenance (noop)\n", result.Repository, result.Target)
			}
			return managedOutput{repository: nullableString(result.Repository), result: result, human: human}, err
		}
		result, err := managed.LocalGC(ctx, managed.LocalGCOptions{
			WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo,
		})
		human := fmt.Sprintf("local gc %s: generation=%s objects=%d bytes=%d\n", result.Repository, result.Generation, result.Objects, result.Bytes)
		if result.Noop {
			human = fmt.Sprintf("local gc %s: no unreachable payloads (noop)\n", result.Repository)
		}
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(result.Operation), result: result, human: human}, err

	case "export rpm-leaf":
		result, err := managed.ExportRPMLeaf(ctx, managed.RPMLeafExportOptions{
			WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo,
			Dist: inv.Positionals[0], Arch: inv.Positionals[1], Directory: inv.Positionals[2], Hardlink: inv.Hardlink,
		})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: fmt.Sprintf(
			"exported RPM leaf %s/%s generation=%s method=%s packages=%d to %s\n",
			result.Dist, result.Arch, result.Generation, result.Method, result.Packages, result.Directory,
		)}, err

	case "log":
		operation := ""
		if len(inv.Positionals) == 1 {
			operation = inv.Positionals[0]
		}
		result, err := managed.Log(ctx, managed.LogOptions{WorkspaceOptions: workspaceOptions, Repository: inv.Global.Repo, Dists: inv.Global.Dists, Operation: operation})
		return managedOutput{repository: nullableString(result.Repository), operation: nullableString(operation), result: result, human: humanJSON(result) + "\n"}, err

	case "log prune":
		before, err := parseBefore(inv.Positionals[0], time.Local)
		if err != nil {
			return managedOutput{}, err
		}
		result, err := managed.PruneLog(ctx, managed.LogPruneOptions{WorkspaceOptions: workspaceOptions, LockOptions: lockOptions, Repository: inv.Global.Repo, Before: before})
		return managedOutput{repository: nullableString(result.Repository), result: result, human: humanJSON(result) + "\n"}, err
	default:
		return managedOutput{}, usageError("unknown command %q", invocationCommand(inv))
	}
}

func loadWorkspace(opts managed.WorkspaceOptions) (config.Workspace, config.Config, error) {
	ws, err := config.Discover(config.DiscoverOptions{Workdir: opts.Workdir, CWD: opts.CWD, SOWDir: opts.SOWDir})
	if err != nil {
		return config.Workspace{}, config.Config{}, Errorf(ErrDiscovery, "%v", err)
	}
	cfg, err := config.LoadWorkspace(ws)
	if err != nil {
		return config.Workspace{}, config.Config{}, Errorf(ErrConfig, "%v", err)
	}
	return ws, cfg, nil
}

func preflightInitConfig(directory string) error {
	root, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	filename := filepath.Join(filepath.Clean(root), config.ConfigFilename)
	_, err = os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := config.Load(filename); err != nil {
		return Errorf(ErrConfig, "%v", err)
	}
	return nil
}

func selectedRepository(ws config.Workspace, cfg config.Config, explicit string) (string, error) {
	selection, err := config.SelectRepository(ws, cfg, config.SelectRepositoryOptions{Explicit: explicit})
	if err != nil {
		if explicit != "" {
			return "", Errorf(ErrRejected, "%v", err)
		}
		return "", Errorf(ErrDiscovery, "%v", err)
	}
	return selection.Name, nil
}

func showConfig(ctx context.Context, inv Invocation, opts managed.WorkspaceOptions) (config.EffectiveConfig, string, error) {
	repository := inv.Global.Repo
	if inv.All {
		repository = ""
	}
	view, err := managed.ShowConfig(ctx, managed.ConfigShowOptions{
		WorkspaceOptions: opts,
		Repository:       inv.Global.Repo,
		Dists:            stableUnique(inv.Global.Dists),
		All:              inv.All,
	})
	if err != nil {
		return config.EffectiveConfig{}, repository, err
	}
	if !inv.All && repository == "" && len(view.Repositories) == 1 {
		for name := range view.Repositories {
			repository = name
		}
	}
	return view, repository, nil
}

func stableUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func classifyManagedError(_ string, err error) error {
	if err == nil {
		return nil
	}
	var partial *managed.PartialError
	switch {
	case errors.As(err, &partial):
		return WithExitCode(ExitPartial, err)
	case errors.Is(err, ErrUsage), errors.Is(err, ErrDiscovery), errors.Is(err, ErrConfig):
		return err
	case errors.Is(err, managed.ErrLockUnavailable):
		return Errorf(ErrLock, "%v", err)
	case errors.Is(err, managed.ErrWorkspaceInput):
		return Errorf(ErrDiscovery, "%v", err)
	case errors.Is(err, managed.ErrIntegrity):
		return Errorf(ErrIntegrity, "%v", err)
	case errors.Is(err, managed.ErrRejected):
		return Errorf(ErrRejected, "%v", err)
	case errors.Is(err, managed.ErrNotReady):
		return Errorf(ErrIntegrity, "%v", err)
	default:
		return err
	}
}

func parseNonnegativeInt64(value, label string) (int64, error) {
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return 0, usageError("%s must be a non-negative decimal integer", label)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, usageError("%s must be a non-negative decimal integer", label)
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, usageError("%s must be a non-negative decimal integer", label)
	}
	return parsed, nil
}

func parseGenerationIDArgument(value string) (state.GenerationID, error) {
	if value == "" || len(value) > 20 || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return 0, usageError("generation must be a decimal integer in 0..18446744073709551615")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, usageError("generation must be a decimal integer in 0..18446744073709551615")
		}
	}
	canonical := strings.Repeat("0", 20-len(value)) + value
	parsed, err := state.ParseGenerationID(canonical)
	if err != nil {
		return 0, usageError("generation must be a decimal integer in 0..18446744073709551615")
	}
	return parsed, nil
}

func parseBefore(value string, location *time.Location) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, location)
	if err != nil {
		return time.Time{}, usageError("BEFORE must be YYYY-MM-DD or an RFC 3339 timestamp with timezone")
	}
	return parsed, nil
}

func writeFailure(command string, jsonOutput bool, err error, repository, operation, result any, stdout, stderr io.Writer) int {
	if command == "" {
		command = "unknown"
	}
	if jsonOutput {
		if writeErr := WriteJSON(stdout, NewEnvelope(command, repository, operation, result, err)); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
			return ExitRuntime
		}
	}
	fmt.Fprintln(stderr, err)
	return ExitCode(err)
}

func writeHuman(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitRuntime
	}
	return ExitOK
}

func invocationCommand(inv Invocation) string {
	if inv.Subcommand == "" {
		return inv.Command
	}
	return inv.Command + " " + inv.Subcommand
}

func failureInvocationContext(args []string) (string, bool) {
	// Mirror extractGlobal's option-value and delimiter rules sufficiently to
	// report a parse failure. Raw token searching is unsafe here: an option
	// value is allowed to equal "build" or "--json" and must never be
	// reinterpreted as command/output intent.
	remaining := make([]string, 0, len(args))
	jsonOutput := false
	for index := 0; index < len(args); index++ {
		token := args[index]
		if token == "--" {
			break
		}
		name, _, inline := splitOption(token)
		switch name {
		case "--json":
			if !inline {
				jsonOutput = true
			}
		case "-C", "--workdir", "-r", "--repo", "-d", "--dist", "-T", "--timeout":
			if !inline && index+1 < len(args) {
				index++
			}
		case "-h", "--help", "--version", "-N", "--no-wait":
			// Recognized value-free global options do not participate in
			// command discovery, even when their use is invalid.
		default:
			remaining = append(remaining, token)
		}
	}
	if len(remaining) == 0 {
		return "unknown", jsonOutput
	}
	command := remaining[0]
	switch command {
	case "create", "init", "help", "version", "add", "rm", "ls", "show", "where", "status", "build", "check", "changes", "gc":
		return command, jsonOutput
	case "export":
		if len(remaining) > 1 && remaining[1] == "rpm-leaf" {
			return "export rpm-leaf", jsonOutput
		}
		return command, jsonOutput
	case "log":
		if len(remaining) > 1 && (remaining[1] == "export" || remaining[1] == "prune") {
			return "log " + remaining[1], jsonOutput
		}
		return "log", jsonOutput
	case "config", "repo", "dist", "retain":
		if len(remaining) > 1 {
			allowed := map[string]map[string]struct{}{
				"config": {"check": {}, "show": {}},
				"repo":   {"ls": {}, "new": {}, "show": {}, "migrate": {}, "rm": {}},
				"dist":   {"ls": {}, "new": {}, "show": {}, "rm": {}},
				"retain": {"add": {}, "ls": {}, "rm": {}},
			}
			if _, ok := allowed[command][remaining[1]]; ok {
				return command + " " + remaining[1], jsonOutput
			}
		}
		return command, jsonOutput
	default:
		return "unknown", jsonOutput
	}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func repositoriesHuman(repositories []managed.RepositoryInfo) string {
	var output strings.Builder
	output.WriteString("NAME\tPROTECTED\tDISTS\tGENERATION\tSTATUS\tPACKAGES\tMEMBERSHIPS\n")
	for _, repository := range repositories {
		fmt.Fprintf(&output, "%s\t%t\t%d\t%d\t%s\t%d\t%d\n", repository.Name, repository.Protected,
			repository.Dists, repository.Generation, repository.Status, repository.Packages, repository.Memberships)
	}
	return output.String()
}

func repositoryHuman(prefix string, repository managed.RepositoryInfo) string {
	return fmt.Sprintf("%s %s: path=%s protected=%t dists=%d generation=%d status=%s packages=%d memberships=%d\n",
		prefix, repository.Name, repository.Path, repository.Protected, repository.Dists, repository.Generation,
		repository.Status, repository.Packages, repository.Memberships)
}

func repositoryShowHuman(repository managed.RepositoryInfo) string {
	var output strings.Builder
	fmt.Fprintf(&output, "repository %s:\n", repository.Name)
	fmt.Fprintf(&output, "  path: %s\n", repository.Path)
	fmt.Fprintf(&output, "  protected: %t\n", repository.Protected)
	fmt.Fprintf(&output, "  dists: %d\n", repository.Dists)
	fmt.Fprintf(&output, "  generation: %d\n", repository.Generation)
	fmt.Fprintf(&output, "  desired_revision: %d\n", repository.DesiredRevision)
	fmt.Fprintf(&output, "  status: %s\n", repository.Status)
	fmt.Fprintf(&output, "  packages: %d\n", repository.Packages)
	fmt.Fprintf(&output, "  memberships: %d\n", repository.Memberships)
	fmt.Fprintf(&output, "  config: %s\n", humanJSON(repository.Config))
	fmt.Fprintf(&output, "  dirty_reasons: %s\n", humanJSON(nonNilStrings(repository.DirtyReasons)))
	if repository.RecentOperation == nil {
		output.WriteString("  recent_operation: null\n")
	} else {
		operation := repository.RecentOperation
		fmt.Fprintf(&output, "  recent_operation: id=%s kind=%s state=%s error_class=%s created_at=%s updated_at=%s\n",
			operation.ID, operation.Kind, operation.State, operation.ErrorClass,
			operation.CreatedAt.UTC().Format(time.RFC3339Nano), operation.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	return output.String()
}

func retainedHuman(generations []managed.RetainedGeneration) string {
	var output strings.Builder
	output.WriteString("GENERATION\tRECORD_IDENTITY\tPATH\n")
	for _, generation := range generations {
		fmt.Fprintf(&output, "%s\t%s\t%s\n", generation.Record.Generation, generation.RecordIdentity, generation.Path)
	}
	return output.String()
}

func distsHuman(dists []managed.DistInfo) string {
	var output strings.Builder
	output.WriteString("NAME\tFORMAT\tARCHITECTURES\tDESIRED\tBUILT\tGENERATION\tDIRTY\tDIRTY_REASONS\n")
	for _, dist := range dists {
		architectures := make([]string, 0, len(dist.Architectures))
		for _, architecture := range dist.Architectures {
			architectures = append(architectures, architecture.Family)
		}
		fmt.Fprintf(&output, "%s\t%s\t%s\t%d\t%d\t%d\t%t\t%s\n", dist.Name, dist.Format,
			strings.Join(architectures, ","), dist.DesiredMembers, dist.BuiltMembers,
			dist.Generation, dist.Dirty, humanJSON(nonNilStrings(dist.DirtyReasons)))
	}
	return output.String()
}

func distHuman(prefix string, dist managed.DistInfo) string {
	architectures := make([]string, 0, len(dist.Architectures))
	for _, architecture := range dist.Architectures {
		architectures = append(architectures, architecture.Family)
	}
	return fmt.Sprintf("%s %s: format=%s architectures=%s members=%d/%d generation=%d dirty=%t\n",
		prefix, dist.Name, dist.Format, strings.Join(architectures, ","), dist.BuiltMembers,
		dist.DesiredMembers, dist.Generation, dist.Dirty)
}

func distShowHuman(dist managed.DistInfo) string {
	architectures := make([]string, 0, len(dist.Architectures))
	for _, architecture := range dist.Architectures {
		architectures = append(architectures, architecture.Family)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "dist %s:\n", dist.Name)
	fmt.Fprintf(&output, "  format: %s\n", dist.Format)
	fmt.Fprintf(&output, "  architectures: %s\n", strings.Join(architectures, ","))
	fmt.Fprintf(&output, "  desired_members: %d\n", dist.DesiredMembers)
	fmt.Fprintf(&output, "  built_members: %d\n", dist.BuiltMembers)
	fmt.Fprintf(&output, "  generation: %d\n", dist.Generation)
	fmt.Fprintf(&output, "  status: %s\n", dist.Status)
	fmt.Fprintf(&output, "  dirty: %t\n", dist.Dirty)
	fmt.Fprintf(&output, "  dirty_reasons: %s\n", humanJSON(nonNilStrings(dist.DirtyReasons)))
	return output.String()
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func humanJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("null /* unavailable: %s */", err)
	}
	return string(data)
}
