package managed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestConcurrentInitAcrossProcessesConvergesOnOneLock(t *testing.T) {
	base := t.TempDir()
	for index := range 16 {
		root := filepath.Join(base, fmt.Sprintf("workspace-%02d", index))
		barrier := filepath.Join(base, fmt.Sprintf("barrier-%02d", index))
		if err := os.Mkdir(barrier, 0o700); err != nil {
			t.Fatal(err)
		}
		commands := make([]*exec.Cmd, 2)
		outputs := make([]string, 2)
		for process := range commands {
			command := exec.Command(os.Args[0], "-test.run=^TestManagedConcurrentInitHelper$")
			command.Env = append(os.Environ(),
				"SOW_MANAGED_CONCURRENT_INIT_HELPER=1",
				"SOW_MANAGED_CONCURRENT_INIT_ROOT="+root,
				"SOW_MANAGED_CONCURRENT_INIT_BARRIER="+barrier,
				fmt.Sprintf("SOW_MANAGED_CONCURRENT_INIT_ID=%d", process),
			)
			commands[process] = command
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for process := range commands {
			ready := filepath.Join(barrier, fmt.Sprintf("ready-%d", process))
			for {
				if _, err := os.Lstat(ready); err == nil {
					break
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if time.Now().After(deadline) {
					t.Fatalf("concurrent init helper %d did not reach barrier", process)
				}
				time.Sleep(time.Millisecond)
			}
		}
		if err := os.WriteFile(filepath.Join(barrier, "start"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for process, command := range commands {
			if err := command.Wait(); err != nil {
				outputs[process] = err.Error()
			}
		}
		if outputs[0] != "" || outputs[1] != "" {
			t.Fatalf("concurrent init pair %d failed: %q %q", index, outputs[0], outputs[1])
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		if _, err := CheckConfig(context.Background(), options); err != nil {
			t.Fatalf("concurrent init pair %d final config: %v", index, err)
		}
		lockPath := filepath.Join(root, ".sow", "workspace.lock")
		info, err := os.Lstat(lockPath)
		var raw unix.Stat_t
		statErr := unix.Lstat(lockPath, &raw)
		if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 || raw.Nlink != 1 {
			t.Fatalf("concurrent init pair %d lock is unsafe: info=%#v stat=%#v err=%v", index, info, raw, errors.Join(err, statErr))
		}
	}
}

func TestManagedConcurrentInitHelper(t *testing.T) {
	if os.Getenv("SOW_MANAGED_CONCURRENT_INIT_HELPER") != "1" {
		return
	}
	root := os.Getenv("SOW_MANAGED_CONCURRENT_INIT_ROOT")
	barrier := os.Getenv("SOW_MANAGED_CONCURRENT_INIT_BARRIER")
	id := os.Getenv("SOW_MANAGED_CONCURRENT_INIT_ID")
	if root == "" || barrier == "" || id == "" {
		t.Fatal("concurrent init helper environment is incomplete")
	}
	if err := os.WriteFile(filepath.Join(barrier, "ready-"+id), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(filepath.Join(barrier, "start")); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent init helper barrier timed out")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
}
