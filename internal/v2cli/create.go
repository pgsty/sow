package v2cli

import (
	"context"
	"fmt"
	"io"

	"github.com/pgsty/sow/internal/v2/plain"
)

type PlainCreateFunc func(context.Context, plain.Options) (plain.Result, error)

// ExecuteCreate adapts the isolated P0 domain operation to the public CLI
// output and exit-code contract. Parse must already have validated inv.
func ExecuteCreate(ctx context.Context, inv Invocation, stdout, stderr io.Writer, create PlainCreateFunc) int {
	if create == nil {
		create = plain.Create
	}
	directory := "."
	if len(inv.Positionals) == 1 {
		directory = inv.Positionals[0]
	}
	result, err := create(ctx, plain.Options{
		Dir: directory, Jobs: inv.Jobs, Pigsty: inv.Pigsty,
		SignWith: inv.SignWith, Overwrite: inv.Overwrite,
		Timeout: inv.Global.Timeout, NoWait: inv.Global.NoWait,
	})
	if err != nil {
		classified := classifyPlainError(err)
		if inv.Global.JSON {
			if writeErr := WriteJSON(stdout, NewEnvelope("create", nil, nil, result, classified)); writeErr != nil {
				fmt.Fprintln(stderr, writeErr)
				return ExitRuntime
			}
		}
		fmt.Fprintln(stderr, err)
		return ExitCode(classified)
	}
	if inv.Global.JSON {
		if err := WriteJSON(stdout, NewEnvelope("create", nil, nil, result)); err != nil {
			fmt.Fprintln(stderr, err)
			return ExitRuntime
		}
		return ExitOK
	}
	if _, err := fmt.Fprintf(stdout, "created %s: rpm=%d deb=%d signed=%d removed=%d marker=%t noop=%t recovered=%t\n",
		result.Dir, result.RPM, result.DEB, len(result.Signed), len(result.Removed), result.Marker, result.Noop, result.Recovered); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitRuntime
	}
	return ExitOK
}

func classifyPlainError(err error) error {
	switch plain.KindOf(err) {
	case plain.KindUsage:
		return Errorf(ErrUsage, "%v", err)
	case plain.KindLock:
		return Errorf(ErrLock, "%v", err)
	case plain.KindIntegrity:
		return Errorf(ErrIntegrity, "%v", err)
	case plain.KindRejected:
		return Errorf(ErrRejected, "%v", err)
	default:
		return err
	}
}
