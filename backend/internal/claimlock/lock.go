package claimlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	leaseName = "bomhort-ingestion-queue-claims"
	// Kubernetes' defaults: a dead holder blocks claims for at most 15s.
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

var (
	// maxHold bounds one critical section. client-go releases a Lease whose
	// renewal failed no earlier than renewDeadline after it started, and
	// other holders wait leaseDuration, so a result that is ready before
	// maxHold (measured from before acquisition) was written while we held it.
	maxHold = renewDeadline / 2
)

// ErrLeaseLost reports a critical section that may have overlapped another
// holder; its result must be discarded.
var ErrLeaseLost = errors.New("claim lock lost or held too long; result discarded")

type Locker interface {
	WithLock(context.Context, func(context.Context) error) error
}

type localLocker struct {
	gate chan struct{}
}

// Local serialises callers inside one process only. Separate worker
// processes (Docker Compose replicas) are not serialised by it.
func Local() Locker {
	return &localLocker{gate: make(chan struct{}, 1)}
}

func (l *localLocker) WithLock(ctx context.Context, fn func(context.Context) error) error {
	select {
	case l.gate <- struct{}{}:
		defer func() { <-l.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return fn(ctx)
}

type kubernetesLocker struct {
	local Locker
	lock  resourcelock.Interface
}

func New(workerID string) (Locker, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
			return Local(), nil
		}
		return nil, errors.New("POD_NAMESPACE is required for the Kubernetes claim lock")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config for claim lock: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client for claim lock: %w", err)
	}
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		leaseName,
		client.CoreV1(),
		client.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: workerID + "/" + uuid.NewString()},
	)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes Lease lock: %w", err)
	}
	return &kubernetesLocker{local: Local(), lock: lock}, nil
}

func (l *kubernetesLocker) WithLock(ctx context.Context, fn func(context.Context) error) error {
	return l.local.WithLock(ctx, func(ctx context.Context) error {
		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// shortcut: monotonic time stops during host suspend, so a suspended
		// (not merely paused) node can overrun maxHold unnoticed; acceptable for pods.
		start := time.Now()
		started := make(chan struct{})
		result := make(chan error, 1)
		runDone := make(chan struct{})
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            l.lock,
			LeaseDuration:   leaseDuration,
			RenewDeadline:   renewDeadline,
			RetryPeriod:     retryPeriod,
			ReleaseOnCancel: true,
			Name:            leaseName,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					close(started)
					fnCtx, cancelFn := context.WithDeadline(leaderCtx, start.Add(maxHold))
					stopCancel := context.AfterFunc(ctx, cancelFn)
					err := fn(fnCtx)
					if leaderCtx.Err() != nil || time.Since(start) >= maxHold {
						err = ErrLeaseLost
					}
					result <- err
					stopCancel()
					cancelFn()
					cancel()
				},
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			return fmt.Errorf("configure Kubernetes claim lock: %w", err)
		}
		go func() {
			elector.Run(runCtx)
			close(runDone)
		}()
		select {
		case err := <-result:
			<-runDone
			return err
		case <-ctx.Done():
			select {
			case <-started:
				err := <-result
				<-runDone
				if err != nil {
					return err
				}
				return ctx.Err()
			default:
				cancel()
				<-runDone
				return ctx.Err()
			}
		case <-runDone:
			select {
			case err := <-result:
				return err
			case <-started:
				return <-result
			default:
				return errors.New("Kubernetes claim lock stopped before acquiring the lease")
			}
		}
	})
}
