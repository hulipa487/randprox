package proxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"randprox/internal/accounting"
	"randprox/internal/db"
	"randprox/internal/wireguard"
)

const proxyAuthHeaderKey = "Proxy-Authorization"
const space = " "

// HTTPServer is an HTTP CONNECT proxy server
type HTTPServer struct {
	db          *db.DB
	deviceMgr   *wireguard.DeviceManager
	accountant  *accounting.TrafficAccountant
}

// NewHTTPServer creates a new HTTP proxy server
func NewHTTPServer(database *db.DB, deviceMgr *wireguard.DeviceManager, accountant *accounting.TrafficAccountant) *HTTPServer {
	return &HTTPServer{
		db:         database,
		deviceMgr:  deviceMgr,
		accountant: accountant,
	}
}

func responseWith(req *http.Request, statusCode int) *http.Response {
	statusText := http.StatusText(statusCode)
	body := "randprox:" + space + req.Proto + space + fmt.Sprint(statusCode) + space + statusText + "\r\n"

	return &http.Response{
		StatusCode: statusCode,
		Status:     statusText,
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func (s *HTTPServer) authenticate(req *http.Request) (*db.User, int, error) {
	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return nil, http.StatusProxyAuthRequired, fmt.Errorf("%s", http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return nil, http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}

	user, err := s.db.VerifyUser(string(pairs[0]), string(pairs[1]))
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("username and password not matching")
	}

	return user, 0, nil
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn, user *db.User, tun *wireguard.VirtualTun) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = tun.Tnet.Dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		peer = nil
	}

	return
}

func (s *HTTPServer) serve(conn net.Conn) {
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		log.Printf("read request failed: %s\n", err)
		return
	}

	user, code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		log.Println(err)
		return
	}

	// Get WireGuard device for user
	tun, err := s.deviceMgr.GetDevice(user.Username, user.WireGuardConfig)
	if err != nil {
		log.Printf("failed to get wireguard device for user %s: %s\n", user.Username, err)
		_ = responseWith(req, http.StatusServiceUnavailable).Write(conn)
		return
	}

	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:
		peer, err = s.handleConn(req, conn, user, tun)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		log.Printf("unsupported protocol: %s\n", req.Method)
		return
	}
	if err != nil {
		log.Printf("dial proxy failed: %s\n", err)
		return
	}
	if peer == nil {
		log.Println("dial proxy failed: peer nil")
		return
	}

	// Copy with traffic accounting
	go func() {
		defer func() { _ = conn.Close() }()
		defer func() { _ = peer.Close() }()

		// peer -> conn (download for user)
		copied, err := io.Copy(conn, peer)
		if copied > 0 {
			s.accountant.RecordTraffic(user.ID, 0, uint64(copied))
		}
		if err != nil && err != io.EOF {
			log.Printf("copy error (peer->conn): %s\n", err)
		}
	}()

	go func() {
		defer func() { _ = conn.Close() }()
		defer func() { _ = peer.Close() }()

		// conn -> peer (upload for user)
		copied, err := io.Copy(peer, conn)
		if copied > 0 {
			s.accountant.RecordTraffic(user.ID, uint64(copied), 0)
		}
		if err != nil && err != io.EOF {
			log.Printf("copy error (conn->peer): %s\n", err)
		}
	}()
}

// ListenAndServe starts the HTTP proxy server
func (s *HTTPServer) ListenAndServe(network, addr string) error {
	server, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("listen tcp failed: %w", err)
	}
	defer func(server net.Listener) {
		_ = server.Close()
	}(server)
	log.Printf("HTTP proxy listening on %s\n", addr)
	for {
		conn, err := server.Accept()
		if err != nil {
			return fmt.Errorf("accept request failed: %w", err)
		}
		go func(conn net.Conn) {
			s.serve(conn)
		}(conn)
	}
}
