package state

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	processIdentityLinuxV1  = "linux-proc-v1"
	processIdentityDarwinV1 = "darwin-kinfo-v1"
)

var (
	errProcessIdentityNotFound    = errors.New("process instance does not exist")
	errProcessIdentityUnavailable = errors.New("process instance identity is unavailable")

	processIdentitySource = struct {
		sync.RWMutex
		read         func(int) (processIdentity, error)
		cacheCurrent bool
	}{read: readPlatformProcessIdentity, cacheCurrent: true}

	currentPlatformProcessIdentity processIdentityCache
)

type processIdentityCache struct {
	sync.Mutex
	identity processIdentity
	set      bool
}

// processIdentity names an OS process instance rather than merely a PID. The
// boot token separates PID namespaces across host boots and the start token
// separates PID reuse within one boot.
type processIdentity struct {
	Scheme     string `json:"scheme"`
	BootToken  string `json:"boot_token"`
	StartToken string `json:"start_token"`
}

func readProcessIdentity(pid int) (processIdentity, error) {
	processIdentitySource.RLock()
	reader := processIdentitySource.read
	cacheCurrent := processIdentitySource.cacheCurrent
	processIdentitySource.RUnlock()
	if reader == nil {
		return processIdentity{}, errProcessIdentityUnavailable
	}
	if cacheCurrent && pid == os.Getpid() {
		return currentPlatformProcessIdentity.read(pid, reader)
	}
	return readAndValidateProcessIdentity(pid, reader)
}

// read pins the first successful platform identity for this still-running Go
// process. A process cannot change its own creation identity without losing
// this address space; re-querying kern.proc or /proc on every lock boundary
// only introduces a transient host-observation failure window. Errors are not
// cached. Other PIDs and injected test readers always remain live probes.
func (c *processIdentityCache) read(pid int, reader func(int) (processIdentity, error)) (processIdentity, error) {
	c.Lock()
	defer c.Unlock()
	if c.set {
		return c.identity, nil
	}
	identity, err := readAndValidateProcessIdentity(pid, reader)
	if err != nil {
		return processIdentity{}, err
	}
	c.identity = identity
	c.set = true
	return identity, nil
}

func readAndValidateProcessIdentity(pid int, reader func(int) (processIdentity, error)) (processIdentity, error) {
	identity, err := reader(pid)
	if err != nil {
		return processIdentity{}, err
	}
	if err := identity.validate(); err != nil {
		return processIdentity{}, fmt.Errorf("validate process instance identity: %w", err)
	}
	return identity, nil
}

// replaceProcessIdentityReader is intentionally package-private. Focused
// tests use it to model PID reuse without depending on the host PID allocator.
func replaceProcessIdentityReader(reader func(int) (processIdentity, error)) func() {
	processIdentitySource.Lock()
	previous := processIdentitySource.read
	previousCacheCurrent := processIdentitySource.cacheCurrent
	processIdentitySource.read = reader
	processIdentitySource.cacheCurrent = false
	processIdentitySource.Unlock()
	return func() {
		processIdentitySource.Lock()
		processIdentitySource.read = previous
		processIdentitySource.cacheCurrent = previousCacheCurrent
		processIdentitySource.Unlock()
	}
}

func (p processIdentity) validate() error {
	switch p.Scheme {
	case processIdentityLinuxV1:
		if !validBootID(p.BootToken) {
			return errors.New("Linux boot token is not a canonical boot ID")
		}
		if !validPositiveDecimal(p.StartToken) {
			return errors.New("Linux process start token is invalid")
		}
	case processIdentityDarwinV1:
		if !validTimevalToken(p.BootToken) {
			return errors.New("Darwin boot token is invalid")
		}
		if !validTimevalToken(p.StartToken) {
			return errors.New("Darwin process start token is invalid")
		}
	default:
		return fmt.Errorf("unsupported process identity scheme %q", p.Scheme)
	}
	return nil
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}

func validPositiveDecimal(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func formatTimevalToken(seconds, microseconds int64) (string, error) {
	if seconds <= 0 || microseconds < 0 || microseconds >= 1_000_000 {
		return "", errors.New("timeval is outside the canonical range")
	}
	return fmt.Sprintf("%d:%06d", seconds, microseconds), nil
}

func validTimevalToken(value string) bool {
	secondsText, microsText, found := strings.Cut(value, ":")
	if !found || len(microsText) != 6 {
		return false
	}
	seconds, secondsErr := strconv.ParseInt(secondsText, 10, 64)
	microseconds, microsErr := strconv.ParseInt(microsText, 10, 64)
	if secondsErr != nil || microsErr != nil {
		return false
	}
	canonical, err := formatTimevalToken(seconds, microseconds)
	return err == nil && canonical == value
}

func parseLinuxProcStatStartToken(pid int, data []byte) (string, error) {
	_, startToken, err := parseLinuxProcStatIdentity(pid, data)
	return startToken, err
}

func parseLinuxProcStatIdentity(pid int, data []byte) (string, string, error) {
	if pid <= 0 {
		return "", "", errors.New("process PID must be positive")
	}
	line := strings.TrimSpace(string(data))
	prefix := strconv.Itoa(pid) + " ("
	if !strings.HasPrefix(line, prefix) {
		return "", "", errors.New("proc stat PID does not match the requested process")
	}
	closing := strings.LastIndex(line, ") ")
	if closing < len(prefix) {
		return "", "", errors.New("proc stat command field is malformed")
	}
	// After the command's closing parenthesis, fields begin at field 3
	// (state). Linux starttime is field 22, therefore index 19 here.
	fields := strings.Fields(line[closing+2:])
	if len(fields) <= 19 {
		return "", "", errors.New("proc stat is missing the process start field")
	}
	if len(fields[0]) != 1 {
		return "", "", errors.New("proc stat process state field is invalid")
	}
	if !validPositiveDecimal(fields[19]) {
		return "", "", errors.New("proc stat process start field is invalid")
	}
	return fields[0], fields[19], nil
}

func linuxProcessStateIsDead(state string) bool {
	return state == "Z" || state == "X" || state == "x"
}
