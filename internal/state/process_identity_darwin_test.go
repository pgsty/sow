//go:build darwin

package state

import (
	"errors"
	"os"
	"testing"
)

func TestDarwinProcessIdentityRuntimeClassification(t *testing.T) {
	identity, err := readPlatformProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatalf("read current Darwin process identity: %v", err)
	}
	if identity.Scheme != processIdentityDarwinV1 {
		t.Fatalf("current Darwin identity scheme=%q want=%q", identity.Scheme, processIdentityDarwinV1)
	}
	if err := identity.validate(); err != nil {
		t.Fatalf("current Darwin identity is invalid: %v", err)
	}

	deadPID := definitelyDeadPID(t)
	if _, err := readPlatformProcessIdentity(deadPID); !errors.Is(err, errProcessIdentityNotFound) {
		t.Fatalf("dead Darwin pid %d classification=%v want=%v", deadPID, err, errProcessIdentityNotFound)
	}
}

func TestDarwinZombieProcessStatusIsDead(t *testing.T) {
	if !darwinProcessStatusIsDead(darwinProcessStatusZombie) {
		t.Fatal("Darwin SZOMB status was not classified as dead")
	}
	for _, status := range []int8{0, 1, 2, 3, 4, 6} {
		if darwinProcessStatusIsDead(status) {
			t.Fatalf("live/non-zombie Darwin status %d was classified as dead", status)
		}
	}
}
