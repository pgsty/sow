package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type verificationTestDriver struct {
	mutex       sync.Mutex
	bodies      map[string][]byte
	failures    map[string]error
	delays      map[string]time.Duration
	closeErrors map[string]error
	opens       int
	active      int
	peak        int
	closed      map[string]int
}

func newVerificationTestDriver() *verificationTestDriver {
	return &verificationTestDriver{
		bodies: make(map[string][]byte), failures: make(map[string]error),
		delays: make(map[string]time.Duration), closeErrors: make(map[string]error),
		closed: make(map[string]int),
	}
}

func (d *verificationTestDriver) preflight(context.Context, Plan) error { return nil }
func (d *verificationTestDriver) acquire(context.Context, Request, string, []byte, []byte) (string, bool, error) {
	return "", false, errors.New("unused")
}
func (d *verificationTestDriver) getControl(context.Context, string) (ControlObject, error) {
	return ControlObject{}, errors.New("unused")
}
func (d *verificationTestDriver) head(context.Context, string) (ObjectInfo, error) {
	return ObjectInfo{}, errors.New("unused")
}
func (d *verificationTestDriver) openObject(context.Context, string) (ObjectContent, error) {
	return ObjectContent{}, errors.New("unused")
}
func (d *verificationTestDriver) putImmutable(context.Context, string, io.Reader, int64, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) copyImmutable(context.Context, string, string, int64, string) (bool, error) {
	return false, errors.New("unused")
}
func (d *verificationTestDriver) hasImmutable(context.Context, string, int64, string) (bool, error) {
	return false, errors.New("unused")
}
func (d *verificationTestDriver) requireAdoptedImmutable(context.Context, string, int64, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) putMutable(context.Context, string, io.Reader, int64, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) delete(context.Context, string, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) deleteCheckpointFenced(context.Context, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) verifyDeleteFence(context.Context, string) error {
	return errors.New("unused")
}
func (d *verificationTestDriver) purge(context.Context, []string) error { return errors.New("unused") }
func (d *verificationTestDriver) commit(context.Context, Request, string, []byte) (string, error) {
	return "", errors.New("unused")
}

func (d *verificationTestDriver) openCDN(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	d.mutex.Lock()
	d.opens++
	d.active++
	if d.active > d.peak {
		d.peak = d.active
	}
	delay := d.delays[rawURL]
	failure := d.failures[rawURL]
	body, exists := d.bodies[rawURL]
	closeErr := d.closeErrors[rawURL]
	d.mutex.Unlock()

	defer func() {
		d.mutex.Lock()
		d.active--
		d.mutex.Unlock()
	}()
	if delay != 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if failure != nil {
		return nil, failure
	}
	if !exists {
		return nil, ErrNotFound
	}
	return &verificationTrackingReader{
		Reader: bytes.NewReader(append([]byte(nil), body...)), closeErr: closeErr,
		onClose: func() {
			d.mutex.Lock()
			d.closed[rawURL]++
			d.mutex.Unlock()
		},
	}, nil
}

type verificationTrackingReader struct {
	io.Reader
	closeErr error
	onClose  func()
	closed   bool
}

func (r *verificationTrackingReader) Close() error {
	if !r.closed {
		r.closed = true
		r.onClose()
	}
	return r.closeErr
}

func TestCDNVerificationPoolIsBoundedConcurrentAndClosesBodies(t *testing.T) {
	driver := newVerificationTestDriver()
	expectations := make([]VerifyObject, 0, 12)
	for index := 0; index < 12; index++ {
		url := "https://cdn.test/verify/" + string(rune('a'+index))
		body := []byte("body-" + string(rune('a'+index)))
		driver.bodies[url] = body
		driver.delays[url] = 15 * time.Millisecond
		expectations = append(expectations, VerifyObject{URL: url, Size: int64(len(body)), SHA256: digestBytes(body)})
	}
	publisher := &Publisher{driver: driver, workers: 3}
	if err := publisher.verify(context.Background(), expectations); err != nil {
		t.Fatal(err)
	}
	driver.mutex.Lock()
	defer driver.mutex.Unlock()
	if driver.peak != 3 {
		t.Fatalf("verification concurrency peak=%d want=3", driver.peak)
	}
	if driver.opens != len(expectations) {
		t.Fatalf("CDN opens=%d want=%d", driver.opens, len(expectations))
	}
	for _, expectation := range expectations {
		if driver.closed[expectation.URL] != 1 {
			t.Fatalf("body close count for %s=%d want=1", expectation.URL, driver.closed[expectation.URL])
		}
	}
}

func TestCDNVerificationFiftyThousandObjectClosure(t *testing.T) {
	const objectCount = 50_000
	driver := newVerificationTestDriver()
	body := []byte("verified-object")
	expectations := make([]VerifyObject, 0, objectCount)
	for index := 0; index < objectCount; index++ {
		url := fmt.Sprintf("https://cdn.test/scale/%05d", index)
		driver.bodies[url] = body
		if index < 8 {
			driver.delays[url] = 20 * time.Millisecond
		}
		expectations = append(expectations, VerifyObject{URL: url, Size: int64(len(body)), SHA256: digestBytes(body)})
	}
	started := time.Now()
	if err := (&Publisher{driver: driver, workers: 8}).verify(context.Background(), expectations); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	driver.mutex.Lock()
	defer driver.mutex.Unlock()
	if driver.opens != objectCount || len(driver.closed) != objectCount {
		t.Fatalf("verified opens=%d closed=%d want=%d", driver.opens, len(driver.closed), objectCount)
	}
	if driver.peak != 8 {
		t.Fatalf("verification concurrency peak=%d want=8", driver.peak)
	}
	t.Logf("cdn_verify_50k objects=%d workers=8 peak=%d elapsed=%s", objectCount, driver.peak, elapsed)
}

func TestCDNVerificationReturnsLowestPlanErrorAndCancelsWindow(t *testing.T) {
	driver := newVerificationTestDriver()
	validURL := "https://cdn.test/verify/00-valid"
	firstBadURL := "https://cdn.test/verify/01-first-bad?token=secret"
	laterBadURL := "https://cdn.test/verify/02-later-bad"
	validBody := []byte("valid")
	driver.bodies[validURL] = validBody
	driver.delays[validURL] = 40 * time.Millisecond
	driver.failures[firstBadURL] = errors.New("first failure")
	driver.delays[firstBadURL] = 20 * time.Millisecond
	driver.failures[laterBadURL] = errors.New("later failure")
	driver.delays[laterBadURL] = time.Millisecond
	// These must remain outside the initial sliding window once index 1 fails.
	for index := 3; index < 20; index++ {
		url := "https://cdn.test/verify/never-" + string(rune('a'+index))
		driver.bodies[url] = validBody
	}
	expectations := []VerifyObject{
		{URL: validURL, Size: int64(len(validBody)), SHA256: digestBytes(validBody)},
		{URL: firstBadURL, Size: 1, SHA256: digestBytes([]byte("x"))},
		{URL: laterBadURL, Size: 1, SHA256: digestBytes([]byte("x"))},
	}
	for index := 3; index < 20; index++ {
		url := "https://cdn.test/verify/never-" + string(rune('a'+index))
		expectations = append(expectations, VerifyObject{URL: url, Size: int64(len(validBody)), SHA256: digestBytes(validBody)})
	}
	publisher := &Publisher{driver: driver, workers: 3}
	err := publisher.verify(context.Background(), expectations)
	if err == nil || !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "01-first-bad") || strings.Contains(err.Error(), "02-later-bad") {
		t.Fatalf("deterministic verification error=%v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("verification error leaked URL query: %v", err)
	}
	driver.mutex.Lock()
	defer driver.mutex.Unlock()
	if driver.opens != 3 {
		t.Fatalf("verification opened %d objects after an early error, want bounded initial window 3", driver.opens)
	}
	if driver.closed[validURL] != 1 {
		t.Fatalf("successful in-flight body close count=%d want=1", driver.closed[validURL])
	}
}

func TestCDNVerificationPreservesCancellationAndCloseErrors(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		driver := newVerificationTestDriver()
		url := "https://cdn.test/verify/cancel"
		driver.bodies[url] = []byte("body")
		driver.delays[url] = time.Second
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(10*time.Millisecond, cancel)
		err := (&Publisher{driver: driver, workers: 1}).verify(ctx, []VerifyObject{{URL: url, Size: 4, SHA256: digestBytes([]byte("body"))}})
		if err == nil || !errors.Is(err, ErrVerification) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	})

	t.Run("close-error", func(t *testing.T) {
		driver := newVerificationTestDriver()
		url := "https://cdn.test/verify/close"
		body := []byte("body")
		driver.bodies[url] = body
		driver.closeErrors[url] = errors.New("close failed")
		err := (&Publisher{driver: driver, workers: 1}).verify(context.Background(), []VerifyObject{{URL: url, Size: int64(len(body)), SHA256: digestBytes(body)}})
		if err == nil || !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "close failed") {
			t.Fatalf("close error=%v", err)
		}
		driver.mutex.Lock()
		defer driver.mutex.Unlock()
		if driver.closed[url] != 1 {
			t.Fatalf("close count=%d want=1", driver.closed[url])
		}
	})
}

func TestCDNVerificationRejectsUnboundedWorkerCount(t *testing.T) {
	driver := newVerificationTestDriver()
	url := "https://cdn.test/verify/bounded"
	body := []byte("body")
	driver.bodies[url] = body
	err := (&Publisher{driver: driver, workers: maxPublishWorkers + 1}).verify(context.Background(), []VerifyObject{{
		URL: url, Size: int64(len(body)), SHA256: digestBytes(body),
	}})
	if err == nil || !strings.Contains(err.Error(), "between 1 and 64") {
		t.Fatalf("unbounded verification workers accepted: %v", err)
	}
	driver.mutex.Lock()
	defer driver.mutex.Unlock()
	if driver.opens != 0 {
		t.Fatalf("unbounded verification opened %d CDN objects before rejection", driver.opens)
	}
}
