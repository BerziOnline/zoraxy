package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// StartDynamicForwardRouter create and start a dynamic forward router for
// this plugin
func (p *Plugin) StartDynamicForwardRouter() error {
	// Create a new dpcore object to forward the traffic to the plugin
	targetURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(p.AssignedPort) + p.Spec.DynamicCaptureIngress)
	if err != nil {
		fmt.Println("Failed to parse target URL: "+targetURL.String(), err)
		return err
	}
	thisRouter := dpcore.NewDynamicProxyCore(targetURL, "", &dpcore.DpcoreOptions{})
	p.dynamicRouteProxy = thisRouter
	return nil
}

// StopDynamicForwardRouter stops the dynamic forward router for this plugin
func (p *Plugin) StopDynamicForwardRouter() {
	if p.dynamicRouteProxy != nil {
		p.dynamicRouteProxy = nil
	}
}

// AcceptDynamicRoute returns whether this plugin accepts dynamic route
func (p *Plugin) AcceptDynamicRoute() bool {
	return p.Spec.DynamicCaptureSniff != "" && p.Spec.DynamicCaptureIngress != ""
}

func (p *Plugin) HandleDynamicRoute(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	//Make sure p.Spec.DynamicCaptureSniff and p.Spec.DynamicCaptureIngress are not empty and start with /
	if !p.AcceptDynamicRoute() {
		return false
	}

	//Make sure the paths start with / and do not end with /
	if !strings.HasPrefix(p.Spec.DynamicCaptureSniff, "/") {
		p.Spec.DynamicCaptureSniff = "/" + p.Spec.DynamicCaptureSniff
	}
	p.Spec.DynamicCaptureSniff = strings.TrimSuffix(p.Spec.DynamicCaptureSniff, "/")
	if !strings.HasPrefix(p.Spec.DynamicCaptureIngress, "/") {
		p.Spec.DynamicCaptureIngress = "/" + p.Spec.DynamicCaptureIngress
	}
	p.Spec.DynamicCaptureIngress = strings.TrimSuffix(p.Spec.DynamicCaptureIngress, "/")

	//Send the request to the sniff endpoint
	sniffURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(p.AssignedPort) + p.Spec.DynamicCaptureSniff + "/")
	if err != nil {
		//Error when parsing the sniff URL, let the next plugin handle the request
		return false
	}

	// Create an instance of CustomRequest with the original request's data
	forwardReq := zoraxy_plugin.EncodeForwardRequestPayload(r, clientIP)

	//Generate a unique request ID
	uniqueRequestID := uuid.New().String()

	resp, err := p.callSniff(sniffURL.String(), uniqueRequestID, &forwardReq)
	if err != nil {
		// Error when talking to the sniff endpoint, let the next plugin handle the request
		return false
	}

	if resp.StatusCode == int(zoraxy_plugin.ControlStatusCode_NEED_BODY) {
		// The plugin cannot decide from the headers alone and asked for a
		// bounded prefix of the request body. Read it, keep a copy for the
		// upstream, and ask the sniff endpoint a second time. The second
		// answer is final; another NEED_BODY counts as skip.
		limit := sniffBodyLimit(resp.Header.Get("X-Zoraxy-Body-Limit"))
		if err := attachSniffBody(r, &forwardReq, limit); err != nil {
			return false
		}
		resp, err = p.callSniff(sniffURL.String(), uniqueRequestID, &forwardReq)
		if err != nil || resp.StatusCode == int(zoraxy_plugin.ControlStatusCode_NEED_BODY) {
			return false
		}
	}

	if resp.StatusCode == int(zoraxy_plugin.ControlStatusCode_DENY) {
		// Plugin asked Zoraxy to reject this request. Answer the client directly
		// and do not forward the request anywhere.
		writeSniffDeny(w, resp.Header.Get("X-Zoraxy-Deny-Status"))
		return true
	}

	if resp.StatusCode != http.StatusOK {
		// Sniff endpoint did not return OK, let the next plugin handle the request
		return false
	}

	p.dynamicRouteProxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{
		UseTLS:       false,
		OriginalHost: r.Host,
		ProxyDomain:  "127.0.0.1:" + strconv.Itoa(p.AssignedPort),
		NoCache:      true,
		PathPrefix:   p.Spec.DynamicCaptureIngress,
		AllowUpgrade: true,
		UpstreamHeaders: [][]string{
			{"X-Zoraxy-RequestID", uniqueRequestID},
		},
	})
	return true
}

// Hard upper bound for the body prefix a sniffer may ask for, and the
// default when the plugin does not say how much it wants.
const (
	sniffBodyDefaultLimit = 64 * 1024
	sniffBodyMaxLimit     = 1024 * 1024
)

type sniffResponse struct {
	StatusCode int
	Header     http.Header
}

// callSniff posts the sniff payload to the plugin and returns status and headers.
// The response body is drained and closed here; sniff answers carry no payload.
func (p *Plugin) callSniff(sniffURL string, requestID string, payload *zoraxy_plugin.DynamicSniffForwardRequest) (*sniffResponse, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", sniffURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zoraxy-RequestID", requestID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return &sniffResponse{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}

// sniffBodyLimit parses the X-Zoraxy-Body-Limit header into a byte count
// between 1 and sniffBodyMaxLimit, falling back to the default.
func sniffBodyLimit(header string) int {
	limit, err := strconv.Atoi(header)
	if err != nil || limit <= 0 {
		return sniffBodyDefaultLimit
	}
	if limit > sniffBodyMaxLimit {
		return sniffBodyMaxLimit
	}
	return limit
}

// attachSniffBody reads at most limit bytes of the request body into the
// sniff payload and puts them back in front of the remaining body, so the
// upstream (or the plugin ingress) still sees the complete, unchanged request.
func attachSniffBody(r *http.Request, payload *zoraxy_plugin.DynamicSniffForwardRequest, limit int) error {
	payload.BodyIncluded = true
	payload.Body = []byte{}
	payload.BodyTruncated = false
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	original := r.Body
	buf, err := io.ReadAll(io.LimitReader(original, int64(limit)+1))
	if err != nil {
		// Do not turn a failed upload into a successful partial request upstream.
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), readError{err}, original), Closer: original}
		return err
	}
	r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), original), Closer: original}
	if len(buf) > limit {
		payload.BodyTruncated = true
		buf = buf[:limit]
	}
	payload.Body = buf
	return nil
}

type replayBody struct {
	io.Reader
	io.Closer
}

type readError struct{ err error }

func (e readError) Read([]byte) (int, error) { return 0, e.err }

// writeSniffDeny answers the client with the status a plugin chose
// (400-599, default 403). A deny can never turn into a success status.
func writeSniffDeny(w http.ResponseWriter, statusHeader string) {
	status := http.StatusForbidden
	if v, err := strconv.Atoi(statusHeader); err == nil && v >= 400 && v <= 599 {
		status = v
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(http.StatusText(status)))
}
