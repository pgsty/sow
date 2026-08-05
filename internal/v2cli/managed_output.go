package v2cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/v2/managed"
)

func mutationHuman(command string, result managed.AddResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "%s repository=%s operation=%s accepted=%d failed=%d memberships=+%d/-%d revision=%d generation=%d dirty=%t\n",
		command, result.Repository, result.Operation, result.Accepted, result.Failed, result.MembershipAdded, result.MembershipRemoved,
		result.Revision, result.Generation, result.Dirty)
	for _, item := range result.Items {
		distNames := make([]string, 0, len(item.Dists))
		for name := range item.Dists {
			distNames = append(distNames, name)
		}
		sort.Strings(distNames)
		dists := make([]string, 0, len(distNames))
		for _, name := range distNames {
			dists = append(dists, name+":"+item.Dists[name])
		}
		fmt.Fprintf(&output, "item input=%q status=%s", item.Input, item.Status)
		if item.Format != "" {
			fmt.Fprintf(&output, " format=%s", item.Format)
		}
		if item.Coordinate != "" {
			fmt.Fprintf(&output, " coordinate=%q", item.Coordinate)
		}
		if item.SHA256 != "" {
			fmt.Fprintf(&output, " sha256:%s", item.SHA256)
		}
		if len(dists) != 0 {
			fmt.Fprintf(&output, " dists=%s", strings.Join(dists, ","))
		}
		if item.Error != "" {
			fmt.Fprintf(&output, " error=%q", item.Error)
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func packagesHuman(result managed.PackageListResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "repository=%s dists=%s dirty=%t\n", result.Repository, strings.Join(result.Dists, ","), result.Dirty)
	output.WriteString("SHA256\tCOORDINATE\tDISTS\tBUILT_DISTS\tPOOL_PATH\n")
	for _, object := range result.Packages {
		fmt.Fprintf(&output, "sha256:%s\t%s:%s\t%s\t%s\t%s\n", object.SHA256, object.Format, object.Coordinate,
			strings.Join(object.Dists, ","), strings.Join(object.BuiltDists, ","), object.PoolPath)
	}
	return output.String()
}

func statusHuman(result managed.StatusResult) string {
	return fmt.Sprintf("repository=%s status=%s ready_to_copy=%t revision=%d generation=%d dirty_dists=%s pending=%d/%d locked=%t\n",
		result.Repository, result.Status, result.ReadyToCopy, result.DesiredRevision, result.BuiltGeneration,
		strings.Join(result.DirtyDists, ","), result.Pending.Count, result.Pending.Bytes, result.RepositoryLocked)
}

func checkHuman(result managed.CheckResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "repository=%s status=%s ready_to_copy=%t revision=%d generation=%d\n", result.Repository, result.Status, result.ReadyToCopy, result.Revision, result.Generation)
	for _, layer := range result.Layers {
		fmt.Fprintf(&output, "%s\tok=%t\tchecked=%d", layer.Name, layer.OK, layer.Checked)
		if len(layer.Issues) != 0 {
			fmt.Fprintf(&output, "\tissues=%s", strings.Join(layer.Issues, "; "))
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func changesHuman(result managed.ChangesResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "base=%d generation=%d dirty=%t\n", result.Base, result.Generation, result.Dirty)
	for _, change := range result.Changes {
		fmt.Fprintf(&output, "%s\t%s\t%s\t%d\t%s\n", change.Operation, change.Phase, change.Path, change.Size, change.SHA256)
	}
	return output.String()
}
