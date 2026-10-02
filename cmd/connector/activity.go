package main

import (
	"net/http"
	"sync/atomic"
	"time"
)

// activityTracker counts a request as activity while it runs, so a long confirmation or PIN
// prompt can never be cut short by the idle exit.
type activityTracker struct {
	inFlight atomic.Int64
	lastNano atomic.Int64
}

func newActivityTracker() *activityTracker {
	a := &activityTracker{}
	a.touch()
	return a
}

func (a *activityTracker) touch() { a.lastNano.Store(time.Now().UnixNano()) }

func (a *activityTracker) idleFor() time.Duration {
	if a.inFlight.Load() > 0 {
		return 0
	}
	return time.Since(time.Unix(0, a.lastNano.Load()))
}

func (a *activityTracker) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.inFlight.Add(1)
		defer func() {
			a.inFlight.Add(-1)
			a.touch()
		}()
		next.ServeHTTP(w, r)
	})
}
