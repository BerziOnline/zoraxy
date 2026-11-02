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
			ID:                    "org.example.sniffer",
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
	handled, denial := p.HandleDynamicRoute(rec, req, "203.0.113.5")
	if !handled {
		t.Fatal("deny must count as handled so no other plugin or upstream sees the request")
	}
	if denial == nil || denial.Status != http.StatusForbidden || denial.Reason != "" {
		t.Fatalf("deny must be reported for logging with its status, got %+v", denial)
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
	if handled, denial := p.HandleDynamicRoute(rec, httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5"); handled || denial != nil {
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

func TestHandleDynamicRoute_DenyReportsSanitisedReason(t *testing.T) {
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Zoraxy-Deny-Status", "429")
		w.Header().Set("X-Zoraxy-Deny-Reason", "WAF: SQL injection (942100)")
		w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
	})
	defer stop()

	_, denial := p.HandleDynamicRoute(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5")
	if denial == nil || denial.Status != http.StatusTooManyRequests || denial.Reason != "WAF-SQL-injection-942100" || denial.Plugin == "" || denial.Plugin != sanitizeDenyReason(p.Spec.ID) {
		t.Fatalf("unexpected denial %+v", denial)
	}
}

func TestSanitizeDenyReason(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"crowdsec-ban":           "crowdsec-ban",
		"line1\r\nline2 [x]":     "line1-line2-x",
		"  spaced  ":             "spaced",
		"\u00fcml\u00e4ut":       "ml-ut",
		strings.Repeat("a", 100): strings.Repeat("a", maxDenyReasonLen),
	} {
		if got := sanitizeDenyReason(in); got != want {
			t.Errorf("sanitizeDenyReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func decodeSniff(t *testing.T, r *http.Request) zoraxy_plugin.DynamicSniffForwardRequest {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}
	var p zoraxy_plugin.DynamicSniffForwardRequest
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Error(err)
	}
	return p
}

func TestHandleDynamicRoute_BodyPrefixWithTheOneSniffCall(t *testing.T) {
	var calls []zoraxy_plugin.DynamicSniffForwardRequest
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, decodeSniff(t, r))
		w.WriteHeader(http.StatusOK)
	})
	defer stop()
	p.Spec.DynamicCaptureSniffBodyKB = 1

	body := strings.Repeat("0123456789", 200) // 2000 bytes, prefix is 1024
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader(body))
	if handled, _ := p.HandleDynamicRoute(rec, req, "203.0.113.5"); !handled {
		t.Fatal("accept must be handled")
	}
	if len(calls) != 1 {
		t.Fatalf("expected exactly one sniff call, got %d", len(calls))
	}
	if !calls[0].BodyIncluded || len(calls[0].Body) != 1024 || string(calls[0].Body) != body[:1024] || !calls[0].BodyTruncated {
		t.Fatalf("want 1024-byte truncated prefix, got included=%v len=%d truncated=%v", calls[0].BodyIncluded, len(calls[0].Body), calls[0].BodyTruncated)
	}
	if *ingressHits != 1 || rec.Header().Get("X-Ingress-Body-Len") != "2000" {
		t.Fatalf("ingress must receive the complete original body once, hits=%d len=%s", *ingressHits, rec.Header().Get("X-Ingress-Body-Len"))
	}
}

func TestHandleDynamicRoute_BodyThenDeny(t *testing.T) {
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(string(decodeSniff(t, r).Body), "' OR 1=1") {
			w.WriteHeader(int(zoraxy_plugin.ControlStatusCode_DENY))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()
	p.Spec.DynamicCaptureSniffBodyKB = 64

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("user=admin' OR 1=1--"))
	if handled, denial := p.HandleDynamicRoute(rec, req, "203.0.113.5"); !handled || denial == nil {
		t.Fatal("a deny based on the body must be handled and reported")
	}
	if rec.Code != http.StatusForbidden || *ingressHits != 0 {
		t.Fatalf("expected 403 and no ingress hit, got %d / %d", rec.Code, *ingressHits)
	}
}

func TestHandleDynamicRoute_BodyThenSkipKeepsBodyForUpstream(t *testing.T) {
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		decodeSniff(t, r)
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()
	p.Spec.DynamicCaptureSniffBodyKB = 1

	body := strings.Repeat("x", 5000)
	req := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(body))
	if handled, _ := p.HandleDynamicRoute(httptest.NewRecorder(), req, "203.0.113.5"); handled {
		t.Fatal("skip must not be handled")
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil || string(rest) != body {
		t.Fatalf("upstream must still read the full body after the prefix read, got %d bytes err=%v", len(rest), err)
	}
}

func TestHandleDynamicRoute_NoBodyUnlessDeclaredAndPresent(t *testing.T) {
	var calls []zoraxy_plugin.DynamicSniffForwardRequest
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, decodeSniff(t, r))
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()

	// Not declared: headers only, as before.
	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("user=a"))
	p.HandleDynamicRoute(httptest.NewRecorder(), req, "203.0.113.5")
	// Declared, but the request has no body.
	p.Spec.DynamicCaptureSniffBodyKB = 64
	p.HandleDynamicRoute(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/", nil), "203.0.113.5")
	if len(calls) != 2 || calls[0].BodyIncluded || calls[1].BodyIncluded {
		t.Fatalf("no body may be sent unless declared and present: %+v", calls)
	}
	if rest, _ := io.ReadAll(req.Body); string(rest) != "user=a" {
		t.Fatal("undeclared plugin must not touch the body")
	}
}

func TestSniffBodyLimit(t *testing.T) {
	for kb, want := range map[int]int{-5: 0, 0: 0, 1: 1024, 64: 65536, 1024: 1 << 20, 5000: 1 << 20} {
		if got := sniffBodyLimit(kb); got != want {
			t.Errorf("sniffBodyLimit(%d) = %d, want %d", kb, got, want)
		}
	}
}

func TestHandleDynamicRoute_BodyPrefixAtTheLimitEdges(t *testing.T) {
	var got zoraxy_plugin.DynamicSniffForwardRequest
	p, _, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		got = decodeSniff(t, r)
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()
	p.Spec.DynamicCaptureSniffBodyKB = 1
	for _, n := range []int{1, 1023, 1024, 1025, 2048} {
		for _, chunked := range []bool{false, true} {
			body := strings.Repeat("b", n)
			req := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(body))
			if chunked {
				req.ContentLength = -1 // what the server sets for Transfer-Encoding: chunked
			}
			if handled, _ := p.HandleDynamicRoute(httptest.NewRecorder(), req, "203.0.113.5"); handled {
				t.Fatalf("n=%d chunked=%v: skip must not be handled", n, chunked)
			}
			want := min(n, 1024)
			if !got.BodyIncluded || len(got.Body) != want || got.BodyTruncated != (n > 1024) {
				t.Fatalf("n=%d chunked=%v: got len=%d truncated=%v", n, chunked, len(got.Body), got.BodyTruncated)
			}
			if rest, err := io.ReadAll(req.Body); err != nil || string(rest) != body {
				t.Fatalf("n=%d chunked=%v: upstream got %d of %d bytes (err=%v)", n, chunked, len(rest), n, err)
			}
		}
	}
}

// failingBody yields some bytes and then the error of a client that broke off.
type failingBody struct{ sent bool }

func (f *failingBody) Read(b []byte) (int, error) {
	if !f.sent {
		f.sent = true
		return copy(b, "user=admin"), nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (f *failingBody) Close() error { return nil }

func TestHandleDynamicRoute_AbortedUploadIsAnsweredNotForwarded(t *testing.T) {
	sniffed := 0
	p, ingressHits, stop := startSniffPlugin(t, func(w http.ResponseWriter, r *http.Request) {
		sniffed++
		w.WriteHeader(http.StatusNotImplemented)
	})
	defer stop()
	p.Spec.DynamicCaptureSniffBodyKB = 64
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/login", nil)
	req.Body, req.ContentLength = &failingBody{}, 5000
	if handled, denial := p.HandleDynamicRoute(rec, req, "203.0.113.5"); !handled || denial != nil {
		t.Fatalf("an aborted upload must be answered by Zoraxy, got handled=%v denial=%v", handled, denial)
	}
	if rec.Code != http.StatusBadRequest || sniffed != 0 || *ingressHits != 0 {
		t.Fatalf("want 400 without sniff or ingress, got %d / %d / %d", rec.Code, sniffed, *ingressHits)
	}
}
