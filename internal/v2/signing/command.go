package signing

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// RunGPG leaves stdin available for the signed message. Each process receives
// a fresh, private descriptor and cannot fall back to interactive pinentry.
func RunGPG(command *exec.Cmd, source Source) error {
	if !source.Explicit() {
		return command.Run()
	}
	secret, err := source.Read()
	if err != nil {
		return err
	}
	defer Clear(secret)
	if bytes.ContainsAny(secret, "\r\n") {
		return errors.Join(ErrCredential, errors.New("GPG requires a single-line passphrase"))
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return errors.New("cannot create GPG passphrase channel")
	}
	defer reader.Close()
	defer writer.Close()
	fd := 3 + len(command.ExtraFiles)
	command.ExtraFiles = append(command.ExtraFiles, reader)
	command.Args = append(command.Args, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-fd", strconv.Itoa(fd))
	// A legacy environment secret need not be inherited by GPG itself.
	if source.env != "" {
		environment := command.Environ()
		command.Env = make([]string, 0, len(environment))
		for _, entry := range environment {
			if !strings.HasPrefix(entry, source.env+"=") {
				command.Env = append(command.Env, entry)
			}
		}
	}
	written := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(writer, bytes.NewReader(secret))
		if writeErr == nil {
			_, writeErr = writer.Write([]byte{'\n'})
		}
		_ = writer.Close()
		written <- writeErr
	}()
	runErr := command.Run()
	_ = reader.Close()
	_ = writer.Close()
	writeErr := <-written
	if runErr != nil {
		return runErr
	}
	if writeErr != nil {
		return errors.New("GPG did not consume its passphrase channel")
	}
	return nil
}

// RPMFile snapshots a source into a private file because rpm may invoke GPG
// more than once per package. An exhausted pipe cannot serve a second signer.
// /tmp is outside repository staging and has a predictable macro-safe spelling
// on both supported operating systems. The caller must always run cleanup.
func RPMFile(source Source) (string, func(), error) {
	noop := func() {}
	if !source.Explicit() {
		return "", noop, nil
	}
	secret, err := source.Read()
	if err != nil {
		return "", noop, err
	}
	defer Clear(secret)
	if bytes.ContainsAny(secret, "\r\n") {
		return "", noop, errors.Join(ErrCredential, errors.New("GPG requires a single-line passphrase"))
	}
	dir, err := os.MkdirTemp("/tmp", "sow-gpg-pass-")
	if err != nil {
		return "", noop, errors.New("cannot create private RPM passfile directory")
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "pass")
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		cleanup()
		return "", noop, errors.New("cannot prepare private RPM passfile")
	}
	return path, cleanup, nil
}

// RPMArgs contains paths and fixed flags only, never password bytes. Do not
// replace __gpg_sign_cmd: its calling convention varies between RPM versions.
func RPMArgs(passfile string) []string {
	if passfile == "" {
		return nil
	}
	return []string{
		"--define", "_openpgp_sign gpg",
		"--define", "_gpg_sign_cmd_extra_args --batch --no-tty --pinentry-mode loopback --passphrase-file " + passfile,
	}
}
