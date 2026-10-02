package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestSplitOrigins(t *testing.T) {
	got := splitOrigins(" https://a.example.com, ,https://b.example.com ,")
	want := []string{"https://a.example.com", "https://b.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("splitOrigins = %v, want %v", got, want)
	}
	if got := splitOrigins(""); len(got) != 0 {
		t.Errorf("splitOrigins(\"\") = %v, want none", got)
	}
}

func TestActivityTrackerCountsRunningRequests(t *testing.T) {
	a := newActivityTracker()
	a.lastNano.Store(time.Now().Add(-time.Hour).UnixNano())
	if a.idleFor() < time.Hour {
		t.Fatalf("idleFor = %s, want at least an hour", a.idleFor())
	}

	var duringRequest time.Duration
	h := a.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { duringRequest = a.idleFor() }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if duringRequest != 0 {
		t.Errorf("idleFor during a request = %s, want 0", duringRequest)
	}
	if a.idleFor() > time.Minute {
		t.Errorf("idleFor after a request = %s, want it reset", a.idleFor())
	}
}
