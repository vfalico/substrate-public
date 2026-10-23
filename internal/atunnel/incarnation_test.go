package atunnel

import (
	"github.com/agent-substrate/substrate/internal/atenet"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExpectedIncarnationRefusesReplacementBeforeProxy(t *testing.T) {
	upstream, err := url.Parse("http://actor.internal:80")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, upstream)
	if err := s.Activate("team-a", "actor", "new-uid", testDial); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setActorTransport(t, s, "team-a", "actor", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get(atenet.TargetActorUIDHeader) != "" {
			t.Error("routing UID leaked to actor")
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
	}))
	for _, tc := range []struct {
		name string
		uids []string
		want int
	}{
		{"legacy", nil, http.StatusNoContent}, {"exact", []string{"new-uid"}, http.StatusNoContent},
		{"replaced", []string{"old-uid"}, http.StatusMisdirectedRequest}, {"empty", []string{""}, http.StatusMisdirectedRequest},
		{"duplicate", []string{"new-uid", "new-uid"}, http.StatusMisdirectedRequest}, {"comma", []string{"old-uid,new-uid"}, http.StatusMisdirectedRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := calls
			req := httptest.NewRequest(http.MethodGet, "https://worker/", nil)
			req.Header.Set(atenet.TargetActorHeader, "team-a/actor")
			for _, uid := range tc.uids {
				req.Header.Add(atenet.TargetActorUIDHeader, uid)
			}
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatal(rec.Code, tc.want)
			}
			if tc.want != http.StatusNoContent && calls != before {
				t.Fatal("replacement reached sandbox")
			}
		})
	}
}
