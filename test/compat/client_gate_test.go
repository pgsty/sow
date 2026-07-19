package compat_test

import (
	"testing"
	"time"
)

func TestCompatibilityRequestGateBlocksOnlySelectedGenerationUntilRelease(t *testing.T) {
	log := &requestLog{}
	reached, release, err := log.installGate("/_sow/v1/g/00000000000000000001/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)

	nonmatch := make(chan struct{})
	go func() {
		log.waitAtGate("/_sow/v1/mirrorlist/latest/repo/el10/x86_64.txt")
		close(nonmatch)
	}()
	select {
	case <-nonmatch:
	case <-time.After(time.Second):
		t.Fatal("request gate blocked an unrelated path")
	}

	blocked := make(chan struct{})
	go func() {
		log.waitAtGate("/_sow/v1/g/00000000000000000001/yum/repo/repodata/repomd.xml")
		close(blocked)
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("selected immutable-generation request did not reach the gate")
	}
	select {
	case <-blocked:
		t.Fatal("selected immutable-generation request passed before release")
	case <-time.After(25 * time.Millisecond):
	}

	release()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("selected immutable-generation request remained blocked after release")
	}
	if _, _, err := log.installGate("relative"); err == nil {
		t.Fatal("request gate accepted a relative prefix")
	}
}
