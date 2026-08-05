package v2cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/plain"
)

func TestExecuteCreateJSONAndOptionMapping(t *testing.T) {
	inv, err := Parse([]string{"create", "repo", "-j", "3", "--pigsty", "-S", "E7935D8DB9BD8B20", "--overwrite", "-N", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	var got plain.Options
	var stdout, stderr bytes.Buffer
	code := ExecuteCreate(context.Background(), inv, &stdout, &stderr, func(_ context.Context, options plain.Options) (plain.Result, error) {
		got = options
		return plain.Result{Dir: "/tmp/repo", RPM: 2, DEB: 1, Marker: true, Removed: []string{"old.rpm"}, Signed: []string{"new.rpm"}, Signer: "E7935D8DB9BD8B20"}, nil
	})
	if code != ExitOK || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if got.Dir != "repo" || got.Jobs != 3 || !got.Pigsty || !got.NoWait || got.SignWith != "E7935D8DB9BD8B20" || !got.Overwrite {
		t.Fatalf("options=%#v", got)
	}
	want := `{"schema":"sow.cli/v1","command":"create","ok":true,"repository":null,"operation":null,"result":{"dir":"/tmp/repo","rpm":2,"deb":1,"kept":null,"removed":["old.rpm"],"signed":["new.rpm"],"signer":"E7935D8DB9BD8B20","marker":true,"noop":false,"recovered":false},"errors":[]}`
	if strings.TrimSpace(stdout.String()) != want {
		t.Fatalf("stdout=%s want=%s", stdout.String(), want)
	}
}

func TestExecuteCreateErrorMapping(t *testing.T) {
	tests := []struct {
		kind  plain.ErrorKind
		code  int
		class string
	}{
		{plain.KindUsage, ExitUsage, "usage"},
		{plain.KindRuntime, ExitRuntime, "runtime"},
		{plain.KindLock, ExitLock, "lock"},
		{plain.KindIntegrity, ExitIntegrity, "integrity"},
		{plain.KindRejected, ExitRejected, "rejected"},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			inv, err := Parse([]string{"create", "--json"})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := ExecuteCreate(context.Background(), inv, &stdout, &stderr, func(context.Context, plain.Options) (plain.Result, error) {
				return plain.Result{}, &plain.Error{Kind: test.kind, Op: "test", Err: errors.New("boom")}
			})
			if code != test.code || !strings.Contains(stdout.String(), `"class":"`+test.class+`"`) || !strings.Contains(stderr.String(), "boom") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestExecuteCreateHumanResult(t *testing.T) {
	inv, err := Parse([]string{"create"})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := ExecuteCreate(context.Background(), inv, &stdout, &stderr, func(context.Context, plain.Options) (plain.Result, error) {
		return plain.Result{Dir: "/tmp/repo", Noop: true}, nil
	})
	if code != 0 || stderr.Len() != 0 || stdout.String() != "created /tmp/repo: rpm=0 deb=0 signed=0 removed=0 marker=false noop=true recovered=false\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestExecuteCreateHumanOutputFailureIsRuntime(t *testing.T) {
	inv, err := Parse([]string{"create"})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("closed output")
	var stderr bytes.Buffer
	code := ExecuteCreate(context.Background(), inv, failingWriter{err: want}, &stderr, func(context.Context, plain.Options) (plain.Result, error) {
		return plain.Result{Dir: "/tmp/repo"}, nil
	})
	if code != ExitRuntime || !strings.Contains(stderr.String(), want.Error()) {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
