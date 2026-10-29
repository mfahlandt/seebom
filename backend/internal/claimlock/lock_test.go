package claimlock

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestNewUsesLocalLockOutsideKubernetes(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("POD_NAMESPACE", "")
	if _, err := New("worker"); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRequiresNamespaceInKubernetes(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes")
	t.Setenv("POD_NAMESPACE", "")
	if _, err := New("worker"); err == nil || err.Error() != "POD_NAMESPACE is required for the Kubernetes claim lock" {
		t.Fatalf("New error = %v, want missing-namespace error", err)
	}
}

func TestLocalSerializesCallbacks(t *testing.T) {
	locker := Local()
	started := make(chan struct{})
	release := make(chan struct{})
	secondEntered := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32

	run := func(entered chan<- struct{}, block bool) {
		t.Helper()
		if err := locker.WithLock(context.Background(), func(context.Context) error {
			now := active.Add(1)
			for previous := maxActive.Load(); now > previous; previous = maxActive.Load() {
				if maxActive.CompareAndSwap(previous, now) {
					break
				}
			}
			entered <- struct{}{}
			if block {
				<-release
			}
			active.Add(-1)
			return nil
		}); err != nil {
			t.Errorf("WithLock: %v", err)
		}
	}

	go run(started, true)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first callback did not enter the lock")
	}
	go run(secondEntered, false)
	select {
	case <-secondEntered:
		t.Fatal("second callback entered while the first held the lock")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second callback did not enter after release")
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent callbacks = %d, want 1", got)
	}
}

func TestKubernetesSerializesCallbacksAcrossLockers(t *testing.T) {
	client := fake.NewSimpleClientset()
	newLocker := func(identity string) Locker {
		lock, err := resourcelock.New(
			resourcelock.LeasesResourceLock,
			"test",
			leaseName,
			client.CoreV1(),
			client.CoordinationV1(),
			resourcelock.ResourceLockConfig{Identity: identity},
		)
		if err != nil {
			t.Fatalf("create lease lock: %v", err)
		}
		return &kubernetesLocker{local: Local(), lock: lock}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	first, second := newLocker("first"), newLocker("second")

	go func() {
		firstDone <- first.WithLock(ctx, func(context.Context) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	select {
	case <-firstEntered:
	case err := <-firstDone:
		t.Fatalf("first WithLock returned before callback: %v", err)
	case <-ctx.Done():
		t.Fatalf("first callback did not acquire the Lease; actions: %#v", client.Actions())
	}

	go func() {
		secondDone <- second.WithLock(ctx, func(context.Context) error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second callback entered while the first held the Lease")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first WithLock: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first callback did not release the Lease")
	}
	select {
	case <-secondEntered:
	case <-ctx.Done():
		t.Fatal("second callback did not acquire the released Lease")
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second WithLock: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("second WithLock did not finish: %v", ctx.Err())
	}
}
