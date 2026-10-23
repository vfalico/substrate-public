package atunnel

import (
	"context"
	"errors"
	"github.com/agent-substrate/substrate/internal/atenet"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExecutionGateEveryRequestIncludingPooledTransport(t *testing.T) {
	upstream, err := url.Parse("http://actor.internal:80")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, upstream)
	checks, requests := 0, 0
	available := true
	check := func(context.Context) error {
		checks++
		if !available {
			return errors.New("exact binding unavailable")
		}
		return nil
	}
	if err := s.ActivateChecked("team-a", "actor", "uid", testDial, check); err != nil {
		t.Fatal(err)
	}
	setActorTransport(t, s, "team-a", "actor", roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
	}))
	for i, want := range []int{204, 503, 503, 204} {
		available = i == 0 || i == 3
		req := httptest.NewRequest(http.MethodPost, "https://worker/", nil)
		req.Header.Set(atenet.TargetActorHeader, "team-a/actor")
		req.Header.Set(atenet.TargetActorUIDHeader, "uid")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("request %d status %d want %d", i, w.Code, want)
		}
	}
	if checks != 4 || requests != 2 {
		t.Fatal(checks, requests)
	}
	// CONNECT admission uses the same gate before parsing/dialing upstream.
	available = false
	req := httptest.NewRequest(http.MethodConnect, "https://worker:80", nil)
	req.Host = "worker:80"
	req.Header.Set(atenet.TargetActorHeader, "team-a/actor")
	w := httptest.NewRecorder()
	s.ServeConnectHTTP(w, req)
	if w.Code != 503 || checks != 5 || requests != 2 {
		t.Fatal(w.Code, checks, requests)
	}
}
