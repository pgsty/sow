package signing

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPassfileProcess(t *testing.T) {
	if os.Getenv("SOW_TEST_PASSFILE_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "no-read" {
			os.Exit(23)
		}
		if arg == "--passphrase-fd" {
			fd, _ := strconv.Atoi(os.Args[i+1])
			password, err := io.ReadAll(os.NewFile(uintptr(fd), "password"))
			message, inputErr := io.ReadAll(os.Stdin)
			if err != nil || inputErr != nil || len(password) != MaxBytes+1 || password[len(password)-1] != '\n' || string(message) != "signed message" {
				os.Exit(24)
			}
			for _, argument := range os.Args {
				if strings.Contains(argument, strings.Repeat("p", 20)) {
					os.Exit(25)
				}
			}
			os.Exit(0)
		}
	}
	os.Exit(26)
}

func TestGPGPasswordDescriptorDoesNotConsumeMessageOrHang(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	writePass(t, path, strings.Repeat("p", MaxBytes))
	source, err := Select(context.Background(), "", path, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, noRead := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		args := []string{"-test.run=^TestPassfileProcess$", "--"}
		if noRead {
			args = append(args, "no-read")
		}
		cmd := exec.CommandContext(ctx, os.Args[0], args...)
		cmd.Env = append(os.Environ(), "SOW_TEST_PASSFILE_CHILD=1")
		cmd.Stdin = bytes.NewBufferString("signed message")
		err := RunGPG(cmd, source)
		cancel()
		if (err != nil) != noRead {
			t.Fatalf("descriptor transfer (noRead=%t): %v", noRead, err)
		}
	}
}
