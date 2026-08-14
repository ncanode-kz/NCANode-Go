package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type echoReq struct {
	Value string `json:"value"`
}

type echoResp struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Value   string `json:"value"`
}

func TestHandleSuccess(t *testing.T) {
	s := New(false)
	Handle(s, "POST /echo", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{Status: 200, Message: "OK", Value: req.Value}, nil
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/echo", "application/json", strings.NewReader(`{"value":"hi"}`))
	if err != nil {
		t.Fatalf("post: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var got echoResp
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if got.Value != "hi" || got.Status != 200 || got.Message != "OK" {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestHandleClientError(t *testing.T) {
	s := New(true)
	Handle(s, "POST /fail", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{}, ClientError("bad input", nil)
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/fail", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var got errorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if got.Message != "bad input" {
		t.Fatalf("unexpected message: %+v", got)
	}
}

func TestHandleMalformedJSON(t *testing.T) {
	s := New(false)
	Handle(s, "POST /echo", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{}, nil
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/echo", "application/json", strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("post: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandlePanicRecover(t *testing.T) {
	s := New(false)
	Handle(s, "POST /panic", func(r *http.Request, req echoReq) (echoResp, error) {
		panic("boom")
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/panic", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestDebugDetails(t *testing.T) {
	s := New(true)
	Handle(s, "POST /fail", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{}, ServerError("boom", nil)
	})
	sNoDebug := New(false)
	Handle(sNoDebug, "POST /fail", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{}, ServerError("boom", nil)
	})

	for _, tc := range []struct {
		name      string
		s         *Server
		wantEmpty bool
	}{
		{"debug on", s, false},
		{"debug off", sNoDebug, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.s.Handler())
			defer srv.Close()

			resp, err := http.Post(srv.URL+"/fail", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatalf("post: %s", err)
			}
			defer resp.Body.Close()

			var got errorEnvelope
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %s", err)
			}

			if tc.wantEmpty && got.Details != "" {
				t.Fatalf("expected empty details, got %q", got.Details)
			}
			if !tc.wantEmpty && got.Details == "" {
				t.Fatalf("expected non-empty details")
			}
		})
	}
}

func TestHandleNonAppError(t *testing.T) {
	s := New(false)
	Handle(s, "POST /fail", func(r *http.Request, req echoReq) (echoResp, error) {
		return echoResp{}, errors.New("plain error")
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/fail", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}

	var got errorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if got.Message != "plain error" {
		t.Fatalf("unexpected message: %+v", got)
	}
}

func TestHealth(t *testing.T) {
	s := New(false)
	s.RegisterHealth()

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/actuator/health")
	if err != nil {
		t.Fatalf("get: %s", err)
	}
	defer resp.Body.Close()

	var got healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if got.Status != "UP" {
		t.Fatalf("expected UP, got %q", got.Status)
	}
}
