package v2cli

import (
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestRootHelpSnapshot(t *testing.T) {
	data, err := os.ReadFile("testdata/root-help.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := string(data)
	if got := RootHelp(); got != want {
		t.Fatalf("root help changed:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestHelpTreeIncludesApprovedLocalLifecycle(t *testing.T) {
	wantTopics := []string{
		"", "add", "build", "changes", "check", "config", "config check", "config show", "create", "dist", "dist ls", "dist new", "dist rm", "dist show",
		"export", "export rpm-leaf", "gc", "help", "init", "log", "log export", "log prune", "ls", "publish", "repo", "repo ls", "repo migrate", "repo new", "repo rm", "repo show",
		"retain", "retain add", "retain ls", "retain rm", "rm", "show", "status", "version", "where",
	}
	gotTopics := make([]string, 0, len(helpText))
	for topic := range helpText {
		gotTopics = append(gotTopics, topic)
	}
	sort.Strings(gotTopics)
	if strings.Join(gotTopics, "\n") != strings.Join(wantTopics, "\n") {
		t.Fatalf("help topics=%q want=%q", gotTopics, wantTopics)
	}

	all := strings.ToLower(strings.Join(helpValues(), "\n"))
	for _, forbidden := range []string{
		"sow materialize", "sow promote", "sow route", "sow snapshot", "sow sync", "sow verify",
		"modulemd", "cloudflare", "object storage", " v1",
	} {
		if strings.Contains(all, forbidden) {
			t.Errorf("help exposed forbidden surface %q", forbidden)
		}
	}
}

func TestHelpSupportsRootGroupsLeavesAndInvocation(t *testing.T) {
	for _, topic := range [][]string{
		nil,
		{"config"}, {"config", "check"}, {"config", "show"},
		{"repo"}, {"repo", "ls"}, {"repo", "new"}, {"repo", "show"}, {"repo", "rm"},
		{"repo", "migrate"}, {"retain"}, {"retain", "add"}, {"retain", "ls"}, {"retain", "rm"}, {"gc"},
		{"dist"}, {"dist", "ls"}, {"dist", "new"}, {"dist", "show"}, {"dist", "rm"},
		{"add"}, {"rm"}, {"ls"}, {"show"}, {"where"}, {"status"}, {"build"}, {"check"}, {"changes"}, {"publish"},
		{"log"}, {"log", "export"}, {"log", "prune"},
		{"export"}, {"export", "rpm-leaf"},
		{"create"}, {"init"}, {"help"}, {"version"},
	} {
		if text, ok := HelpTopic(topic...); !ok || text == "" {
			t.Errorf("HelpTopic(%q) missing", topic)
		}
	}
	for _, topic := range [][]string{{"repo", "publish"}, {"dist", "new", "extra"}} {
		if text, ok := HelpTopic(topic...); ok || text != "" {
			t.Errorf("HelpTopic(%q)=%q,%v", topic, text, ok)
		}
	}

	inv, err := Parse([]string{"help", "dist", "new"})
	if err != nil {
		t.Fatal(err)
	}
	if got := Help(inv); !strings.HasPrefix(got, "Usage:\n  sow dist new ") {
		t.Fatalf("invocation help=%q", got)
	}
	inv, err = Parse([]string{"repo", "--help"})
	if err != nil {
		t.Fatal(err)
	}
	if got := Help(inv); !strings.Contains(got, "sow repo COMMAND") {
		t.Fatalf("group help=%q", got)
	}
}

func TestLeafHelpMatchesClosedOptionMatrix(t *testing.T) {
	tests := []struct {
		topic string
		want  []string
		deny  []string
	}{
		{topic: "create", want: []string{"--jobs", "--pigsty", "--sign-with", "--overwrite", "--timeout", "--no-wait", "--json"}, deny: []string{"--workdir", "--repo", "--dist", "--force", "--all", "--format"}},
		{topic: "init", want: []string{"--json"}, deny: []string{"--workdir", "--timeout", "--no-wait", "--repo", "--dist"}},
		{topic: "config check", want: []string{"--workdir", "--json"}, deny: []string{"--repo", "--dist", "--timeout", "--no-wait", "--all"}},
		{topic: "config show", want: []string{"--all", "--workdir", "--repo", "--dist", "--json"}, deny: []string{"--timeout", "--no-wait", "--force"}},
		{topic: "repo ls", want: []string{"--workdir", "--json"}, deny: []string{"--repo", "--dist", "--timeout", "--no-wait", "--force"}},
		{topic: "repo new", want: []string{"--workdir", "--timeout", "--no-wait", "--json"}, deny: []string{"--repo", "--dist", "--force", "--format"}},
		{topic: "repo show", want: []string{"--workdir", "--repo", "--json"}, deny: []string{"--dist", "--timeout", "--no-wait", "--force"}},
		{topic: "repo migrate", want: []string{"--abort", "--jobs", "--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--force", "--format"}},
		{topic: "repo rm", want: []string{"--force", "--workdir", "--timeout", "--no-wait", "--json"}, deny: []string{"--repo", "--dist", "--format"}},
		{topic: "dist ls", want: []string{"--workdir", "--repo", "--json"}, deny: []string{"--dist", "--timeout", "--no-wait", "--force"}},
		{topic: "dist new", want: []string{"--format", "--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--force", "--all"}},
		{topic: "dist show", want: []string{"--workdir", "--repo", "--json"}, deny: []string{"--dist", "--timeout", "--no-wait", "--force"}},
		{topic: "dist rm", want: []string{"--force", "--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--format", "--all"}},
		{topic: "add", want: []string{"--recursive", "--skip", "--jobs", "--workdir", "--repo", "--dist", "--timeout", "--no-wait", "--json"}, deny: []string{"--check", "--force", "--format"}},
		{topic: "rm", want: []string{"--check", "--skip", "--jobs", "--workdir", "--repo", "--dist", "--timeout", "--no-wait", "--json"}, deny: []string{"--recursive", "--force", "--format"}},
		{topic: "ls", want: []string{"--workdir", "--repo", "--dist", "--json"}, deny: []string{"--jobs", "--timeout", "--no-wait"}},
		{topic: "show", want: []string{"--workdir", "--repo", "--dist", "--json"}, deny: []string{"--jobs", "--timeout", "--no-wait"}},
		{topic: "where", want: []string{"--workdir", "--repo", "--dist", "--json"}, deny: []string{"--jobs", "--timeout", "--no-wait"}},
		{topic: "status", want: []string{"--workdir", "--repo", "--dist", "--json"}, deny: []string{"--jobs", "--timeout", "--no-wait"}},
		{topic: "build", want: []string{"--jobs", "--workdir", "--repo", "--dist", "--timeout", "--no-wait", "--json"}, deny: []string{"--skip", "--check", "--force"}},
		{topic: "check", want: []string{"--jobs", "--workdir", "--repo", "--dist", "--json"}, deny: []string{"--timeout", "--no-wait", "--force"}},
		{topic: "changes", want: []string{"--workdir", "--repo", "--json"}, deny: []string{"--dist", "--jobs", "--timeout"}},
		{topic: "publish", want: []string{"--abort", "--workdir", "--timeout", "--no-wait", "--json"}, deny: []string{"--repo", "--dist", "--jobs", "--force"}},
		{topic: "retain add", want: []string{"--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--jobs", "--force"}},
		{topic: "retain ls", want: []string{"--workdir", "--repo", "--json"}, deny: []string{"--dist", "--jobs", "--timeout", "--no-wait"}},
		{topic: "retain rm", want: []string{"--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--jobs", "--force"}},
		{topic: "gc", want: []string{"--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--jobs", "--force"}},
		{topic: "export rpm-leaf", want: []string{"--hardlink", "--workdir", "--repo", "--json"}, deny: []string{"--dist", "--jobs", "--timeout", "--no-wait"}},
		{topic: "log", want: []string{"--workdir", "--repo", "--dist", "--json"}, deny: []string{"--jobs", "--force"}},
		{topic: "log export", want: []string{"--workdir", "--repo", "--dist"}, deny: []string{"--json", "--timeout", "--no-wait"}},
		{topic: "log prune", want: []string{"--workdir", "--repo", "--timeout", "--no-wait", "--json"}, deny: []string{"--dist", "--jobs", "--force"}},
	}
	for _, test := range tests {
		t.Run(test.topic, func(t *testing.T) {
			body, ok := HelpTopic(strings.Fields(test.topic)...)
			if !ok {
				t.Fatal("missing help")
			}
			for _, option := range test.want {
				if !strings.Contains(body, option) {
					t.Errorf("missing option %s", option)
				}
			}
			for _, option := range test.deny {
				if strings.Contains(body, option) {
					t.Errorf("exposed disallowed option %s", option)
				}
			}
		})
	}
}

func TestVersionStringIncludesVersionAndTarget(t *testing.T) {
	previous := Version
	Version = "9.8.7-test"
	t.Cleanup(func() { Version = previous })
	got := VersionString()
	for _, want := range []string{"sow 9.8.7-test", runtime.GOOS + "/" + runtime.GOARCH, runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Errorf("VersionString()=%q missing %q", got, want)
		}
	}
}

func TestDefaultVersionIsRelease(t *testing.T) {
	if Version != "0.3.0" {
		t.Fatalf("default Version=%q, want release 0.3.0", Version)
	}
}

func helpValues() []string {
	values := make([]string, 0, len(helpText))
	for _, value := range helpText {
		values = append(values, value)
	}
	return values
}
