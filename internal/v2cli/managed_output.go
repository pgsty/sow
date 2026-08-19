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

func removeHuman(result managed.RemoveResult) string {
	var output strings.Builder
	action := "removed"
	if result.Check {
		action = "preview"
	}
	fmt.Fprintf(&output, "%s repository=%s operation=%s dists=%s memberships=%d revision=%d generation=%s dirty=%t changes=%d\n",
		action, result.Repository, result.Operation, strings.Join(result.Dists, ","), len(result.Removed), result.Revision, result.Generation, result.Dirty, len(result.Changes))
	for _, item := range result.Removed {
		fmt.Fprintf(&output, "membership dist=%s name=%q coordinate=%q sha256:%s\n", item.Dist, item.Name, item.Coordinate, item.SHA256)
	}
	for _, change := range result.Changes {
		fmt.Fprintf(&output, "change op=%s phase=%s path=%q", change.Operation, change.Phase, change.Path)
		if change.Operation != "delete" {
			fmt.Fprintf(&output, " size=%d sha256:%s", change.Size, change.SHA256)
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func buildHuman(result managed.BuildResult) string {
	if result.Noop {
		return fmt.Sprintf("build repository=%s dists=%s already current (noop) revision=%d generation=%s dirty=%t\n",
			result.Repository, strings.Join(result.Dists, ","), result.Revision, result.Generation, result.Dirty)
	}
	return fmt.Sprintf("built repository=%s operation=%s dists=%s revision=%d generation=%s dirty=%t\n",
		result.Repository, result.Operation, strings.Join(result.Dists, ","), result.Revision, result.Generation, result.Dirty)
}

func packageShowHuman(result managed.PackageShowResult) string {
	object := result.Package
	return fmt.Sprintf("package repository=%s coordinate=%q sha256:%s format=%s architecture=%s size=%d storage=%s\npool=%s\ndists=%s built_dists=%s\n",
		result.Repository, object.Coordinate, object.SHA256, object.Format, object.Architecture, object.Size, object.Storage,
		object.PoolPath, strings.Join(object.Dists, ","), strings.Join(object.BuiltDists, ","))
}

func packageWhereHuman(result managed.PackageWhereResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "reference=%q locations=%d\n", result.Reference, len(result.Locations))
	for _, location := range result.Locations {
		fmt.Fprintf(&output, "repository=%s coordinate=%q sha256:%s dists=%s built_dists=%s\n",
			location.Repository, location.Coordinate, location.SHA256, strings.Join(location.Dists, ","), strings.Join(location.BuiltDists, ","))
	}
	return output.String()
}

func logHuman(result managed.LogResult) string {
	var output strings.Builder
	if result.Detail != nil {
		detail := result.Detail
		operation := detail.Operation
		fmt.Fprintf(&output, "operation=%s repository=%s kind=%s state=%s duration_ms=%d created=%s updated=%s\n",
			operation.ID, result.Repository, operation.Kind, operation.State, detail.DurationMS,
			operation.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"), operation.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))
		fmt.Fprintf(&output, "events=%d packages=%d memberships=%d files=%d\n", len(detail.Events), len(detail.Packages), len(detail.Memberships), len(detail.Files))
		if operation.ErrorClass != "" || operation.ErrorMessage != "" {
			fmt.Fprintf(&output, "error class=%s message=%q\n", operation.ErrorClass, operation.ErrorMessage)
		}
		return output.String()
	}
	fmt.Fprintf(&output, "repository=%s operations=%d\n", result.Repository, len(result.Operations))
	output.WriteString("ID\tKIND\tSTATE\tCREATED\tUPDATED\n")
	for _, operation := range result.Operations {
		fmt.Fprintf(&output, "%s\t%s\t%s\t%s\t%s\n", operation.ID, operation.Kind, operation.State,
			operation.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), operation.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return output.String()
}

func logPruneHuman(result managed.LogPruneResult) string {
	return fmt.Sprintf("pruned log repository=%s operation=%s before=%s operations=%d\n",
		result.Repository, result.Operation, result.Before.UTC().Format("2006-01-02T15:04:05.000000000Z"), result.Pruned)
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
