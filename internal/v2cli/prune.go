package v2cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pgsty/sow/internal/v2/plain"
)

func executePrune(ctx context.Context, inv Invocation, stdout, stderr io.Writer) int {
	result, err := plain.Prune(ctx, plain.PruneOptions{
		Dir: inv.Positionals[0], DryRun: inv.DryRun, Protect: inv.Protect,
		Jobs: inv.Jobs, MetadataTimestamp: inv.MetadataTimestamp,
		Timeout: inv.Global.Timeout, NoWait: inv.Global.NoWait,
	})
	if err != nil {
		err = classifyPlainError(markCommandInterrupted(ctx, err))
		if ExitCode(err) != ExitInterrupted && (result.IndexUpdated || len(result.Removed) != 0) {
			err = WithExitCode(ExitPartial, err)
		}
	}
	if inv.Global.JSON {
		var output any
		if result.Dir != "" {
			output = result
		}
		if writeErr := WriteJSON(stdout, NewEnvelope("prune", nil, nil, output, err)); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
			return ExitRuntime
		}
	} else if result.Dir != "" {
		if code := writeHuman(stdout, stderr, pruneHuman(result, err == nil)); code != ExitOK {
			return code
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitCode(err)
	}
	return ExitOK
}

func pruneHuman(result plain.PruneResult, success bool) string {
	var output strings.Builder
	removed := make(map[string]bool, len(result.Removed))
	for _, path := range result.Removed {
		removed[path] = true
	}
	for _, candidate := range result.Candidates {
		action := "remaining"
		if result.DryRun {
			action = "would remove"
		} else if removed[candidate.Path] {
			action = "removed"
		}
		fmt.Fprintf(&output, "%s %s (keep %s)\n", action, candidate.Path, candidate.Latest)
	}
	action := "pruned"
	if result.DryRun {
		action = "preview"
	}
	if !success {
		action = "prune incomplete"
	}
	fmt.Fprintf(&output, "%s %s: kept=%d candidates=%d removed=%d index_updated=%t noop=%t\n",
		action, result.Dir, len(result.Kept), len(result.Candidates), len(result.Removed), result.IndexUpdated, result.Noop)
	return output.String()
}
