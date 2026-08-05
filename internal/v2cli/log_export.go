package v2cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pgsty/sow/internal/v2/managed"
)

func executeLogExport(ctx context.Context, inv Invocation, stdout, stderr io.Writer) int {
	opts := managed.LogOptions{WorkspaceOptions: managed.WorkspaceOptions{Workdir: inv.Global.Workdir}, Repository: inv.Global.Repo, Dists: inv.Global.Dists}
	target := "-"
	if len(inv.Positionals) == 1 {
		target = inv.Positionals[0]
	}
	if target == "-" {
		if _, err := managed.ExportLog(ctx, opts, stdout); err != nil {
			return writeFailure("log export", false, classifyManagedError("log export", err), nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
		}
		return ExitOK
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	parent := filepath.Dir(absolute)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return writeFailure("log export", false, fmt.Errorf("log export parent is not a real directory: %w", err), nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return writeFailure("log export", false, Errorf(ErrRejected, "export target already exists: %s", absolute), nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	} else if !errors.Is(err, os.ErrNotExist) {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	tmp, err := os.CreateTemp(parent, ".sow-log-export-")
	if err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	count, exportErr := managed.ExportLog(ctx, opts, tmp)
	closeErr := errors.Join(tmp.Sync(), tmp.Close())
	if err := errors.Join(exportErr, closeErr); err != nil {
		return writeFailure("log export", false, classifyManagedError("log export", err), nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	if err := os.Link(tmpName, absolute); err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	if err := os.Remove(tmpName); err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	if directory, err := os.Open(parent); err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	} else if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return writeFailure("log export", false, err, nullableString(inv.Global.Repo), nil, nil, stdout, stderr)
	}
	return writeHuman(stdout, stderr, fmt.Sprintf("exported %d operations to %s\n", count, absolute))
}
