package plugins

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// startSniffPlugin runs a fake plugin sniff endpoint on 127.0.0.1 and returns a
// Plugin that points at it, plus a counter of how many times the ingress was hit.
func startSniffPlugin(t *testing.T, sniff http.HandlerFunc) (*Plugin, *int, func()) {
	t.Helper()
	ingressHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/sniff/", sniff)
	mux.HandleFunc("/ingress/", func(w http.ResponseWriter, r *http.Request) {
		ingressHits++
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Ingress-Body-Len", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	p := &Plugin{
		Enabled:      true,
		AssignedPort: ln.Addr().(*net.TCPAddr).Port,
		Spec: &zoraxy_plugin.IntroSpect{
			DynamicCaptureSniff:   "/sniff",
			DynamicCaptureIngress: "/ingress",
		},
	}
	p.StartDynamicForwardRouter()
	return p, &ingressHits, func() { srv.Close() }
}

func TestHandleDynamicRoute_DenyWithDefaultStatus(t *testing.T) {
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
	})
	defer stop()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/admin?id=1%20OR%201=1", nil)
	if handled := p.HandleDynamicRoute(rec, req, "203.0.113.5"); !handled {
		t.Fatal("deny must count as handled so no other plugin or upstream sees the request")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 by default, got %d", rec.Code)
	}
	if *ingressHits != 0 {
		t.Fatalf("denied request must not reach the plugin ingress, got %d hits", *ingressHits)
	}
}

func TestHandleDynamicRoute_DenyWithPluginStatus(t *testing.T) {
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Zoraxy-Deny-Status", strconv.Itoa(http.StatusTooManyRequests))
		w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
	})
	defer stop()

	rec := httptest.NewRecorder()
	p.HandleDynamicRoute(rec, httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected plugin-chosen 429, got %d", rec.Code)
	}
}

func TestHandleDynamicRoute_DenyIgnoresNonErrorStatus(t *testing.T) {
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Zoraxy-Deny-Status", "200")
		w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
	})
	defer stop()

	rec := httptest.NewRecorder()
	p.HandleDynamicRoute(rec, httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a deny must never turn into a success status, got %d", rec.Code)
	}
}

func TestHandleDynamicRoute_SkipStillFallsThrough(t *testing.T) {
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()

	rec := httptest.NewRecorder()
	if handled := p.HandleDynamicRoute(rec, httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5"); handled {
		t.Fatal("skip must not count as handled")
	}
	if *ingressHits != 0 {
		t.Fatal("skipped request must not reach the plugin ingress")
	}
}

func TestSniffHandler_DenyHelperSetsHeaders(t *testing.T) {
	mux := http.NewServeMux()
	pr := zoraxy_plugin.NewPathRouter()
	pr.RegisterDynamicSniffHandler("/sniff", mux, func(dsfr *zoraxy_plugin.DynamicSniffForwardRequest) zoraxy_plugin.SniffResult {
		return dsfr.Deny(http.StatusNotAcceptable, "test rule 1")
	})

	payload := zoraxy_plugin.EncodeForwardRequestPayload(httptest.NewRequest("GET", "http://example.com/x", nil), "203.0.113.5")
	body, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/sniff/", bytes.NewReader(body)))

	if rec.Code != int(zoraxy_plugin.ControlStatusCode_DENY) {
		t.Fatalf("expected %d, got %d", zoraxy_plugin.ControlStatusCode_DENY, rec.Code)
	}
	if rec.Header().Get("X-Zoraxy-Deny-Status") != "406" || rec.Header().Get("X-Zoraxy-Deny-Reason") != "test rule 1" {
		t.Fatalf("unexpected deny headers: %v", rec.Header())
	}
}

// decodeSniff reads the sniff payload Zoraxy posted to the fake plugin.
func decodeSniff(t *testing.T, r *http.Request) zoraxy_plugin.DynamicSniffForwardRequest {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	var p zoraxy_plugin.DynamicSniffForwardRequest
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHandleDynamicRoute_NeedBodyThenAccept(t *testing.T) {
	var rounds []zoraxy_plugin.DynamicSniffForwardRequest
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		payload := decodeSniff(t, r)
		rounds = append(rounds, payload)
		if !payload.BodyIncluded {
			w.Header().Set("X-Zoraxy-Body-Limit", "8")
			w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_NEED_BODY))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	body := "0123456789abcdef" // 16 bytes, limit is 8
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader(body))
	if !p.HandleDynamicRoute(rec, req, "203.0.113.5") {
		t.Fatal("accept after body round must be handled")
	}
	if len(rounds) != 2 {
		t.Fatalf("expected 2 sniff rounds, got %d", len(rounds))
	}
	if rounds[0].BodyIncluded || len(rounds[0].Body) != 0 {
		t.Fatal("first round must not carry a body")
	}
	if !rounds[1].BodyIncluded || string(rounds[1].Body) != "01234567" || !rounds[1].BodyTruncated {
		t.Fatalf("second round: want 8-byte truncated prefix, got included=%v body=%q truncated=%v", rounds[1].BodyIncluded, rounds[1].Body, rounds[1].BodyTruncated)
	}
	if rounds[1].Method != rounds[0].Method || rounds[1].URL != rounds[0].URL || rounds[1].ClientIP != rounds[0].ClientIP {
		t.Fatalf("second round must repeat the same request metadata, got %+v", rounds[1])
	}
	if *ingressHits != 1 || rec.Header().Get("X-Ingress-Body-Len") != "16" {
		t.Fatalf("ingress must receive the complete original body once, hits=%d len=%s", *ingressHits, rec.Header().Get("X-Ingress-Body-Len"))
	}
}

func TestHandleDynamicRoute_NeedBodyThenDeny(t *testing.T) {
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		payload := decodeSniff(t, r)
		if !payload.BodyIncluded {
			w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_NEED_BODY))
			return
		}
		if strings.Contains(string(payload.Body), "' OR 1=1") {
			w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("user=admin' OR 1=1--"))
	if !p.HandleDynamicRoute(rec, req, "203.0.113.5") {
		t.Fatal("deny after body round must be handled")
	}
	if rec.Code != http.StatusForbidden || *ingressHits != 0 {
		t.Fatalf("expected 403 and no ingress hit, got %d / %d", rec.Code, *ingressHits)
	}
}

func TestHandleDynamicRoute_NeedBodyThenSkipKeepsBodyForUpstream(t *testing.T) {
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		payload := decodeSniff(t, r)
		if !payload.BodyIncluded {
			w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_NEED_BODY))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()

	body := strings.Repeat("x", 100)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(body))
	if p.HandleDynamicRoute(rec, req, "203.0.113.5") {
		t.Fatal("skip after body round must not be handled")
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil || string(rest) != body {
		t.Fatalf("upstream must still read the full body after a sniff prefix read, got %d bytes err=%v", len(rest), err)
	}
}

func TestHandleDynamicRoute_NeedBodyTwiceIsSkip(t *testing.T) {
	calls := 0
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_NEED_BODY))
	})
	defer stop()

	rec := httptest.NewRecorder()
	if p.HandleDynamicRoute(rec, httptest.NewRequest("POST", "http://example.com/", strings.NewReader("abc")), "203.0.113.5") {
		t.Fatal("a second NEED_BODY must count as skip")
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 sniff calls, no loop, got %d", calls)
	}
}

func TestSniffBodyLimit(t *testing.T) {
	cases := map[string]int{
		"":        sniffBodyDefaultLimit,
		"abc":     sniffBodyDefaultLimit,
		"0":       sniffBodyDefaultLimit,
		"-5":      sniffBodyDefaultLimit,
		"1024":    1024,
		"9999999": sniffBodyMaxLimit,
	}
	for in, want := range cases {
		if got := sniffBodyLimit(in); got != want {
			t.Errorf("sniffBodyLimit(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSniffHandler_NeedBodyHelper(t *testing.T) {
	mux := http.NewServeMux()
	pr := zoraxy_plugin.NewPathRouter()
	pr.RegisterDynamicSniffHandler("/sniff", mux, func(dsfr *zoraxy_plugin.DynamicSniffForwardRequest) zoraxy_plugin.SniffResult {
		if !dsfr.BodyIncluded {
			return dsfr.NeedBody(4096)
		}
		return zoraxy_plugin.SniffResultAccept
	})

	// Round 1: no body → plugin asks for one.
	payload := zoraxy_plugin.EncodeForwardRequestPayload(httptest.NewRequest("POST", "http://example.com/x", nil), "203.0.113.5")
	raw, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/sniff/", bytes.NewReader(raw)))
	if rec.Code != int(zoraxy_plugin.ControlStatusCode_NEED_BODY) || rec.Header().Get("X-Zoraxy-Body-Limit") != "4096" {
		t.Fatalf("round 1: expected 287 with limit 4096, got %d %v", rec.Code, rec.Header())
	}

	// Round 2: body included → plugin decides.
	payload.BodyIncluded = true
	payload.Body = []byte("hello")
	raw, _ = json.Marshal(payload)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/sniff/", bytes.NewReader(raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("round 2: expected accept, got %d", rec.Code)
	}

	// A handler that keeps asking for the body on round 2 is answered with skip by the SDK.
	pr2 := zoraxy_plugin.NewPathRouter()
	mux2 := http.NewServeMux()
	pr2.RegisterDynamicSniffHandler("/sniff", mux2, func(dsfr *zoraxy_plugin.DynamicSniffForwardRequest) zoraxy_plugin.SniffResult {
		return dsfr.NeedBody(0)
	})
	rec = httptest.NewRecorder()
	mux2.ServeHTTP(rec, httptest.NewRequest("POST", "/sniff/", bytes.NewReader(raw)))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("NEED_BODY on round 2 must become skip, got %d", rec.Code)
	}
}
