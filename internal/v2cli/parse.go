package v2cli

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// GlobalOptions are syntactically global but are accepted only when the
// selected command's closed option matrix permits them.
type GlobalOptions struct {
	Workdir string
	Repo    string
	Dists   []string
	Timeout time.Duration
	NoWait  bool
	JSON    bool

	workdirSet bool
	repoSet    bool
	timeoutSet bool
	noWaitSet  bool
	jsonSet    bool
	distSet    bool
}

type Invocation struct {
	Command     string
	Subcommand  string
	Positionals []string
	Global      GlobalOptions
	Help        bool
	Version     bool
	Jobs        int
	Pigsty      bool
	SignWith    string
	Overwrite   bool
	All         bool
	Force       bool
	Format      string
	Recursive   bool
	Skip        bool
	Check       bool
}

type optionUse uint16

const (
	useWorkdir optionUse = 1 << iota
	useRepo
	useDist
	useTimeout
	useNoWait
	useJSON
)

type commandSpec struct {
	globals   optionUse
	minArgs   int
	maxArgs   int
	jobs      bool
	pigsty    bool
	signWith  bool
	overwrite bool
	all       bool
	force     bool
	format    bool
	recursive bool
	skip      bool
	check     bool
}

var commandSpecs = map[string]commandSpec{
	"create":       {globals: useTimeout | useNoWait | useJSON, minArgs: 0, maxArgs: 1, jobs: true, pigsty: true, signWith: true, overwrite: true},
	"init":         {globals: useJSON, minArgs: 0, maxArgs: 1},
	"config check": {globals: useWorkdir | useJSON},
	"config show":  {globals: useWorkdir | useRepo | useDist | useJSON, all: true},
	"repo ls":      {globals: useWorkdir | useJSON},
	"repo new":     {globals: useWorkdir | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1},
	"repo show":    {globals: useWorkdir | useRepo | useJSON, minArgs: 0, maxArgs: 1},
	"repo rm":      {globals: useWorkdir | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1, force: true},
	"dist ls":      {globals: useWorkdir | useRepo | useJSON},
	"dist new":     {globals: useWorkdir | useRepo | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1, format: true},
	"dist show":    {globals: useWorkdir | useRepo | useJSON, minArgs: 1, maxArgs: 1},
	"dist rm":      {globals: useWorkdir | useRepo | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1, force: true},
	"add":          {globals: useWorkdir | useRepo | useDist | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1 << 30, jobs: true, recursive: true, skip: true},
	"rm":           {globals: useWorkdir | useRepo | useDist | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1 << 30, jobs: true, skip: true, check: true},
	"ls":           {globals: useWorkdir | useRepo | useDist | useJSON},
	"show":         {globals: useWorkdir | useRepo | useDist | useJSON, minArgs: 1, maxArgs: 1},
	"where":        {globals: useWorkdir | useRepo | useDist | useJSON, minArgs: 1, maxArgs: 1},
	"status":       {globals: useWorkdir | useRepo | useDist | useJSON},
	"build":        {globals: useWorkdir | useRepo | useDist | useTimeout | useNoWait | useJSON, jobs: true},
	"check":        {globals: useWorkdir | useRepo | useDist | useJSON, jobs: true},
	"changes":      {globals: useWorkdir | useRepo | useJSON, minArgs: 0, maxArgs: 1},
	"log":          {globals: useWorkdir | useRepo | useDist | useJSON, minArgs: 0, maxArgs: 1},
	"log export":   {globals: useWorkdir | useRepo | useDist, minArgs: 0, maxArgs: 1},
	"log prune":    {globals: useWorkdir | useRepo | useTimeout | useNoWait | useJSON, minArgs: 1, maxArgs: 1},
}

var errUsage = errors.New("usage error")

var publicDurationPattern = regexp.MustCompile(`^\+?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:ms|s|m|h))+$`)
var gpgKeyIDPattern = regexp.MustCompile(`(?i)^(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})$`)

func usageError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// Parse accepts common options before or after the command while enforcing the
// API contract's per-command closed option set.
func Parse(args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{Help: true, Jobs: runtime.NumCPU()}, nil
	}
	remaining, global, help, version, err := extractGlobal(args)
	if err != nil {
		return Invocation{}, err
	}
	inv := Invocation{Global: global, Help: help, Version: version, Jobs: runtime.NumCPU()}
	if version && len(remaining) == 0 {
		if err := validateGlobalUse("version", global, 0); err != nil {
			return Invocation{}, err
		}
		return inv, nil
	}
	if version {
		return Invocation{}, usageError("--version cannot be combined with a command or arguments")
	}
	if len(remaining) == 0 {
		if help {
			if err := validateGlobalUse("help", global, 0); err != nil {
				return Invocation{}, err
			}
			return inv, nil
		}
		return Invocation{}, usageError("command is required")
	}
	if remaining[0] == "help" {
		if err := validateGlobalUse("help", global, 0); err != nil {
			return Invocation{}, err
		}
		inv.Command = "help"
		inv.Positionals = remaining[1:]
		if len(inv.Positionals) > 2 {
			return Invocation{}, usageError("help accepts at most a command and subcommand")
		}
		return inv, nil
	}
	if remaining[0] == "version" {
		if err := validateGlobalUse("version", global, 0); err != nil {
			return Invocation{}, err
		}
		if len(remaining) != 1 {
			return Invocation{}, usageError("version accepts no arguments")
		}
		inv.Command = "version"
		inv.Version = true
		return inv, nil
	}

	inv.Command = remaining[0]
	remaining = remaining[1:]
	if inv.Command == "config" || inv.Command == "repo" || inv.Command == "dist" {
		if len(remaining) == 0 {
			if help {
				if err := validateGlobalUse(inv.Command+" help", global, 0); err != nil {
					return Invocation{}, err
				}
				return inv, nil
			}
			return Invocation{}, usageError("%s subcommand is required", inv.Command)
		}
		inv.Subcommand = remaining[0]
		remaining = remaining[1:]
	} else if inv.Command == "log" && len(remaining) != 0 && (remaining[0] == "export" || remaining[0] == "prune") {
		inv.Subcommand = remaining[0]
		remaining = remaining[1:]
	}
	key := inv.Command
	if inv.Subcommand != "" {
		key += " " + inv.Subcommand
	}
	spec, ok := commandSpecs[key]
	if !ok {
		return Invocation{}, usageError("unknown command %q", key)
	}
	if err := validateGlobalUse(key, global, spec.globals); err != nil {
		return Invocation{}, err
	}
	if global.NoWait && global.Timeout != 0 {
		return Invocation{}, usageError("--no-wait and non-zero --timeout are mutually exclusive")
	}
	positionals, err := parseLocal(remaining, spec, &inv)
	if err != nil {
		return Invocation{}, err
	}
	inv.Positionals = positionals
	if inv.Help {
		return inv, nil
	}
	if inv.Overwrite && inv.SignWith == "" {
		return Invocation{}, usageError("--overwrite requires --sign-with")
	}
	if inv.Check && inv.Skip {
		return Invocation{}, usageError("--check and --skip are mutually exclusive")
	}
	if inv.Command == "rm" && inv.Check && (global.timeoutSet || global.noWaitSet) {
		return Invocation{}, usageError("rm --check does not accept --timeout or --no-wait")
	}
	if len(positionals) < spec.minArgs || len(positionals) > spec.maxArgs {
		return Invocation{}, usageError("%s expects %s", key, argumentRange(spec.minArgs, spec.maxArgs))
	}
	if key == "log" && len(positionals) == 1 {
		if _, err := parseNonnegativeInt64(positionals[0], "operation"); err != nil {
			return Invocation{}, err
		}
	}
	if spec.format && inv.Format == "" {
		return Invocation{}, usageError("%s requires --format rpm|deb", key)
	}
	return inv, nil
}

func extractGlobal(args []string) ([]string, GlobalOptions, bool, bool, error) {
	remaining := make([]string, 0, len(args))
	var out GlobalOptions
	var help, version bool
	stopped := false
	for i := 0; i < len(args); i++ {
		token := args[i]
		if stopped {
			remaining = append(remaining, token)
			continue
		}
		if token == "--" {
			stopped = true
			remaining = append(remaining, token)
			continue
		}
		name, inline, hasInline := splitOption(token)
		switch name {
		case "-h", "--help":
			if hasInline {
				return nil, out, false, false, usageError("%s takes no value", name)
			}
			help = true
		case "--version":
			if hasInline {
				return nil, out, false, false, usageError("--version takes no value")
			}
			version = true
		case "-N", "--no-wait":
			if hasInline || out.noWaitSet {
				return nil, out, false, false, usageError("%s is duplicated or has a value", name)
			}
			out.NoWait, out.noWaitSet = true, true
		case "--json":
			if hasInline || out.jsonSet {
				return nil, out, false, false, usageError("--json is duplicated or has a value")
			}
			out.JSON, out.jsonSet = true, true
		case "-C", "--workdir", "-r", "--repo", "-d", "--dist", "-T", "--timeout":
			value := inline
			if !hasInline {
				if i+1 >= len(args) {
					return nil, out, false, false, usageError("%s requires a value", name)
				}
				i++
				value = args[i]
			}
			if value == "" {
				return nil, out, false, false, usageError("%s requires a non-empty value", name)
			}
			switch name {
			case "-C", "--workdir":
				if out.workdirSet {
					return nil, out, false, false, usageError("--workdir is duplicated")
				}
				out.Workdir, out.workdirSet = value, true
			case "-r", "--repo":
				if out.repoSet {
					return nil, out, false, false, usageError("--repo is duplicated")
				}
				out.Repo, out.repoSet = value, true
			case "-d", "--dist":
				out.Dists, out.distSet = append(out.Dists, value), true
			case "-T", "--timeout":
				if out.timeoutSet {
					return nil, out, false, false, usageError("--timeout is duplicated")
				}
				duration, parseErr := parseDuration(value)
				if parseErr != nil {
					return nil, out, false, false, parseErr
				}
				out.Timeout, out.timeoutSet = duration, true
			}
		default:
			remaining = append(remaining, token)
		}
	}
	return remaining, out, help, version, nil
}

func parseLocal(args []string, spec commandSpec, inv *Invocation) ([]string, error) {
	positionals := make([]string, 0, len(args))
	stopped := false
	jobsSet, pigstySet, signWithSet, overwriteSet, allSet, forceSet, formatSet := false, false, false, false, false, false, false
	recursiveSet, skipSet, checkSet := false, false, false
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" && !stopped {
			stopped = true
			continue
		}
		if stopped || token == "-" || !strings.HasPrefix(token, "-") {
			positionals = append(positionals, token)
			continue
		}
		name, inline, hasInline := splitOption(token)
		switch name {
		case "-j", "--jobs":
			if !spec.jobs || jobsSet {
				return nil, usageError("option %s is not allowed or is duplicated", name)
			}
			value, next, err := optionValue(args, i, name, inline, hasInline)
			if err != nil {
				return nil, err
			}
			i = next
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				return nil, usageError("--jobs must be an integer greater than or equal to 1")
			}
			inv.Jobs, jobsSet = n, true
		case "--pigsty":
			if !spec.pigsty || pigstySet || hasInline {
				return nil, usageError("option --pigsty is not allowed, duplicated, or has a value")
			}
			inv.Pigsty, pigstySet = true, true
		case "-S", "--sign-with":
			if !spec.signWith || signWithSet {
				return nil, usageError("option %s is not allowed or is duplicated", name)
			}
			value, next, err := optionValue(args, i, name, inline, hasInline)
			if err != nil {
				return nil, err
			}
			i = next
			value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
			if !gpgKeyIDPattern.MatchString(value) {
				return nil, usageError("--sign-with must be a 16, 40, or 64 hexadecimal GPG key ID/fingerprint")
			}
			inv.SignWith, signWithSet = strings.ToUpper(value), true
		case "--overwrite":
			if !spec.overwrite || overwriteSet || hasInline {
				return nil, usageError("option --overwrite is not allowed, duplicated, or has a value")
			}
			inv.Overwrite, overwriteSet = true, true
		case "--all":
			if !spec.all || allSet || hasInline {
				return nil, usageError("option --all is not allowed, duplicated, or has a value")
			}
			inv.All, allSet = true, true
		case "-f", "--force":
			if !spec.force || forceSet || hasInline {
				return nil, usageError("option %s is not allowed, duplicated, or has a value", name)
			}
			inv.Force, forceSet = true, true
		case "--format":
			if !spec.format || formatSet {
				return nil, usageError("option --format is not allowed or is duplicated")
			}
			value, next, err := optionValue(args, i, name, inline, hasInline)
			if err != nil {
				return nil, err
			}
			i = next
			if value != "rpm" && value != "deb" {
				return nil, usageError("--format must be rpm or deb")
			}
			inv.Format, formatSet = value, true
		case "-R", "--recursive":
			if !spec.recursive || recursiveSet || hasInline {
				return nil, usageError("option %s is not allowed, duplicated, or has a value", name)
			}
			inv.Recursive, recursiveSet = true, true
		case "--skip":
			if !spec.skip || skipSet || hasInline {
				return nil, usageError("option --skip is not allowed, duplicated, or has a value")
			}
			inv.Skip, skipSet = true, true
		case "-c", "--check":
			if !spec.check || checkSet || hasInline {
				return nil, usageError("option %s is not allowed, duplicated, or has a value", name)
			}
			inv.Check, checkSet = true, true
		default:
			return nil, usageError("unknown option %q", token)
		}
	}
	return positionals, nil
}

func validateGlobalUse(command string, global GlobalOptions, allowed optionUse) error {
	checks := []struct {
		set  bool
		use  optionUse
		name string
	}{
		{global.workdirSet, useWorkdir, "--workdir"},
		{global.repoSet, useRepo, "--repo"},
		{global.distSet, useDist, "--dist"},
		{global.timeoutSet, useTimeout, "--timeout"},
		{global.noWaitSet, useNoWait, "--no-wait"},
		{global.jsonSet, useJSON, "--json"},
	}
	for _, check := range checks {
		if check.set && allowed&check.use == 0 {
			return usageError("%s is not allowed for %s", check.name, command)
		}
	}
	return nil
}

func parseDuration(value string) (time.Duration, error) {
	if value == "0" {
		return 0, nil
	}
	if !publicDurationPattern.MatchString(value) {
		return 0, usageError("--timeout must be 0 or a positive Go duration using ms, s, m, or h")
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, usageError("--timeout must be 0 or a positive Go duration using ms, s, m, or h")
	}
	return duration, nil
}

func splitOption(token string) (string, string, bool) {
	if index := strings.IndexByte(token, '='); index >= 0 {
		return token[:index], token[index+1:], true
	}
	return token, "", false
}

func optionValue(args []string, index int, name, inline string, hasInline bool) (string, int, error) {
	if hasInline {
		if inline == "" {
			return "", index, usageError("%s requires a non-empty value", name)
		}
		return inline, index, nil
	}
	if index+1 >= len(args) {
		return "", index, usageError("%s requires a value", name)
	}
	return args[index+1], index + 1, nil
}

func argumentRange(minimum, maximum int) string {
	if minimum == maximum {
		return fmt.Sprintf("exactly %d positional argument(s)", minimum)
	}
	return fmt.Sprintf("between %d and %d positional argument(s)", minimum, maximum)
}
