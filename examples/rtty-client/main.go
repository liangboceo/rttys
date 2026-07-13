package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	msgTypeRegister = iota
	msgTypeLogin
	msgTypeLogout
	msgTypeTermData
	msgTypeWinsize
	msgTypeCmd
	msgTypeHeartbeat
	msgTypeFile
	msgTypeHttp
	msgTypeAck
)

const (
	msgTypeFileSend = iota
	msgTypeFileRecv
	msgTypeFileInfo
	msgTypeFileData
	msgTypeFileAck
	msgTypeFileAbort
)

const (
	protoVersion      = byte(4)
	heartbeatInterval = 5 * time.Second
	maxMsgSize        = 0xffff
)

type Client struct {
	addr              string
	id                string
	desc              string
	token             string
	useTLS            bool
	insecure          bool
	root              string
	httpHost          string
	httpPort          int
	reconnectInterval time.Duration
	conn              net.Conn
	reader            *bufio.Reader
	start             time.Time
	writeMu           sync.Mutex
	sessions          map[string]*Session
	sessionMu         sync.Mutex
	files             map[string]*FileTransfer
	fileMu            sync.Mutex
	tunnels           map[string]*TunnelTarget
	tunnelMu          sync.RWMutex
}

type Session struct {
	sid    string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	closed chan struct{}
}

type FileTransfer struct {
	file *os.File
	path string
}

type TunnelTarget struct {
	port  int
	proto string
}

type cmdResponse struct {
	Token string `json:"token"`
	Attrs string `json:"attrs"`
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:5912", "rttys device listen address")
	id := flag.String("id", defaultDeviceID(), "device id")
	desc := flag.String("desc", "rtty-client on "+runtime.GOOS+"/"+runtime.GOARCH, "device description")
	token := flag.String("token", "", "device token, must match rttys token config when enabled")
	useTLS := flag.Bool("tls", false, "connect with TLS")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	root := flag.String("root", ".", "file protocol root directory")
	httpHost := flag.String("http-host", "127.0.0.1", "default host for legacy msgTypeHttp proxy target")
	httpPort := flag.Int("http-port", 80, "default port for legacy msgTypeHttp proxy target")
	reconnect := flag.Duration("reconnect", 5*time.Second, "reconnect interval, set 0 to disable")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatalf("invalid root: %v", err)
	}

	c := &Client{
		addr:              *addr,
		id:                *id,
		desc:              *desc,
		token:             *token,
		useTLS:            *useTLS,
		insecure:          *insecure,
		root:              absRoot,
		httpHost:          *httpHost,
		httpPort:          *httpPort,
		reconnectInterval: *reconnect,
		sessions:          make(map[string]*Session),
		files:             make(map[string]*FileTransfer),
		tunnels:           make(map[string]*TunnelTarget),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Run(ctx); err != nil {
		log.Fatalf("rtty-client stopped: %v", err)
	}
}

func defaultDeviceID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "rtty-client"
	}
	return host
}

func (c *Client) Run(ctx context.Context) error {
	for {
		if err := c.runOnce(ctx); err != nil {
			if ctx.Err() != nil || c.reconnectInterval <= 0 {
				return err
			}
			log.Printf("connection closed: %v; reconnecting in %s", err, c.reconnectInterval)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.reconnectInterval):
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	if err := c.connect(); err != nil {
		return err
	}
	defer c.conn.Close()
	defer c.closeAllSessions()
	defer c.closeAllFiles()

	c.start = time.Now()
	log.Printf("connected to %s as device %s", c.addr, c.id)

	if err := c.writeMsg(msgTypeRegister, c.buildRegisterMsg()); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	heartbeatCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.heartbeatLoop(heartbeatCtx)
	return c.readLoop()
}

func (c *Client) connect() error {
	var conn net.Conn
	var err error
	if c.useTLS {
		conn, err = tls.Dial("tcp", c.addr, &tls.Config{InsecureSkipVerify: c.insecure})
	} else {
		conn, err = net.Dial("tcp", c.addr)
	}
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

func (c *Client) buildRegisterMsg() []byte {
	payload := []byte{protoVersion}
	payload = append(payload, []byte(c.id)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(c.desc)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(c.token)...)
	return payload
}

func (c *Client) writeMsg(typ byte, data []byte) error {
	if len(data) > maxMsgSize {
		return fmt.Errorf("message too large: %d", len(data))
	}

	header := []byte{typ, 0, 0}
	binary.BigEndian.PutUint16(header[1:], uint16(len(data)))

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.conn.Write(append(header, data...))
	return err
}

func (c *Client) readMsg() (byte, []byte, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return 0, nil, err
	}
	msgLen := binary.BigEndian.Uint16(header[1:])
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(c.reader, data); err != nil {
		return 0, nil, err
	}
	return header[0], data, nil
}

func (c *Client) readLoop() error {
	for {
		typ, data, err := c.readMsg()
		if err != nil {
			return err
		}

		switch typ {
		case msgTypeRegister:
			c.handleRegisterAck(data)
		case msgTypeLogin:
			c.handleLogin(data)
		case msgTypeLogout:
			c.handleLogout(data)
		case msgTypeTermData:
			c.handleTermData(data)
		case msgTypeWinsize:
			c.handleWinsize(data)
		case msgTypeCmd:
			go c.handleCmd(data)
		case msgTypeHeartbeat:
			_ = c.sendHeartbeat()
		case msgTypeFile:
			go c.handleFile(data)
		case msgTypeHttp:
			go c.handleHTTP(data)
		case msgTypeAck:
			log.Printf("recv ack bytes=%d", len(data))
		default:
			log.Printf("ignore unknown msg type=%d bytes=%d", typ, len(data))
		}
	}
}

func (c *Client) handleRegisterAck(data []byte) {
	if len(data) == 0 {
		log.Printf("register ack: empty")
		return
	}
	log.Printf("register ack: code=%d msg=%q", data[0], string(data[1:]))
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				log.Printf("send heartbeat failed: %v", err)
				return
			}
		}
	}
}

func (c *Client) sendHeartbeat() error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(time.Since(c.start).Seconds()))
	return c.writeMsg(msgTypeHeartbeat, payload)
}

func (c *Client) handleLogin(data []byte) {
	if len(data) < 32 {
		log.Printf("invalid login msg bytes=%d", len(data))
		return
	}
	sid := string(data[:32])
	log.Printf("session login: %s", sid)

	s, err := c.startShellSession(sid)
	ack := append([]byte{}, data[:32]...)
	if err != nil {
		log.Printf("start shell failed sid=%s: %v", sid, err)
		ack = append(ack, 1)
		_ = c.writeMsg(msgTypeLogin, ack)
		return
	}

	c.sessionMu.Lock()
	c.sessions[sid] = s
	c.sessionMu.Unlock()

	ack = append(ack, 0)
	_ = c.writeMsg(msgTypeLogin, ack)
}

func (c *Client) startShellSession(sid string) (*Session, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	s := &Session{sid: sid, cmd: cmd, stdin: stdin, closed: make(chan struct{})}
	pipeOutput := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				_ = c.writeMsg(msgTypeTermData, append([]byte(sid), buf[:n]...))
			}
			if err != nil {
				return
			}
		}
	}
	go pipeOutput(stdout)
	go pipeOutput(stderr)
	go func() {
		_ = cmd.Wait()
		close(s.closed)
		_ = c.writeMsg(msgTypeLogout, []byte(sid))
	}()

	return s, nil
}

func (c *Client) handleLogout(data []byte) {
	if len(data) < 32 {
		return
	}
	sid := string(data[:32])
	c.closeSession(sid)
	log.Printf("session logout: %s", sid)
}

func (c *Client) closeSession(sid string) {
	c.sessionMu.Lock()
	s := c.sessions[sid]
	delete(c.sessions, sid)
	c.sessionMu.Unlock()
	if s != nil && s.cmd != nil && s.cmd.Process != nil {
		_ = s.stdin.Close()
		_ = s.cmd.Process.Kill()
	}
}

func (c *Client) closeAllSessions() {
	c.sessionMu.Lock()
	sids := make([]string, 0, len(c.sessions))
	for sid := range c.sessions {
		sids = append(sids, sid)
	}
	c.sessionMu.Unlock()
	for _, sid := range sids {
		c.closeSession(sid)
	}
}

func (c *Client) handleTermData(data []byte) {
	if len(data) < 32 {
		return
	}
	sid := string(data[:32])
	payload := data[32:]
	c.sessionMu.Lock()
	s := c.sessions[sid]
	c.sessionMu.Unlock()
	if s == nil || s.stdin == nil {
		return
	}
	_, _ = s.stdin.Write(payload)
}

func (c *Client) handleWinsize(data []byte) {
	if len(data) < 36 {
		return
	}
	sid := string(data[:32])
	cols := binary.BigEndian.Uint16(data[32:34])
	rows := binary.BigEndian.Uint16(data[34:36])
	log.Printf("winsize sid=%s cols=%d rows=%d", sid, cols, rows)
}

func (c *Client) handleCmd(data []byte) {
	parts := bytes.Split(data, []byte{0})
	if len(parts) < 5 {
		log.Printf("invalid cmd request bytes=%d", len(data))
		return
	}

	cmdText := string(parts[2])
	token := string(parts[3])
	paramCount := int(0)
	if len(parts[4]) > 0 {
		paramCount = int(parts[4][0])
	}
	params := make([]string, 0, paramCount)
	for i := 0; i < paramCount && 5+i < len(parts); i++ {
		params = append(params, string(parts[5+i]))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdText, params...)
	if len(params) == 0 && strings.ContainsAny(cmdText, " \t|&;<>()$`\\\"'") {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdText)
	}
	out, err := cmd.CombinedOutput()
	resp := cmdResponse{Token: token, Attrs: string(out)}
	if err != nil {
		resp.Code = 1
		resp.Error = err.Error()
	}
	b, _ := json.Marshal(resp)
	_ = c.writeMsg(msgTypeCmd, b)
}

func (c *Client) handleFile(data []byte) {
	if len(data) < 33 {
		return
	}
	sid := string(data[:32])
	typ := data[32]
	payload := data[33:]

	switch typ {
	case msgTypeFileInfo:
		if len(payload) < 4 {
			return
		}
		size := binary.BigEndian.Uint32(payload[:4])
		path := safePath(c.root, string(payload[4:]))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			log.Printf("file mkdir failed sid=%s path=%s: %v", sid, path, err)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
			return
		}
		f, err := os.Create(path)
		if err != nil {
			log.Printf("file create failed sid=%s path=%s: %v", sid, path, err)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
			return
		}
		c.fileMu.Lock()
		if old := c.files[sid]; old != nil && old.file != nil {
			_ = old.file.Close()
		}
		c.files[sid] = &FileTransfer{file: f, path: path}
		c.fileMu.Unlock()
		log.Printf("file receive start sid=%s path=%s size=%d", sid, path, size)
		_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAck, nil))
	case msgTypeFileData:
		c.fileMu.Lock()
		ft := c.files[sid]
		c.fileMu.Unlock()
		if len(payload) == 0 {
			c.closeFile(sid)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAck, nil))
			log.Printf("file receive done sid=%s", sid)
			return
		}
		if ft == nil || ft.file == nil {
			log.Printf("file data without file info sid=%s", sid)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
			return
		}
		if _, err := ft.file.Write(payload); err != nil {
			log.Printf("file write failed sid=%s path=%s: %v", sid, ft.path, err)
			c.closeFile(sid)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
			return
		}
		_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAck, nil))
	case msgTypeFileSend:
		path := safePath(c.root, string(payload))
		go c.sendFile(sid, path)
	case msgTypeFileRecv:
		log.Printf("file recv request acknowledged sid=%s", sid)
		_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAck, nil))
	case msgTypeFileAbort:
		c.closeFile(sid)
		log.Printf("file abort sid=%s", sid)
	default:
		log.Printf("file unknown sid=%s type=%d bytes=%d", sid, typ, len(payload))
	}
}

func (c *Client) sendFile(sid, path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("file open failed sid=%s path=%s: %v", sid, path, err)
		_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
		return
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if err := c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileData, buf[:n])); err != nil {
				log.Printf("file send failed sid=%s: %v", sid, err)
				return
			}
		}
		if err == io.EOF {
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileData, nil))
			log.Printf("file send done sid=%s path=%s", sid, path)
			return
		}
		if err != nil {
			log.Printf("file read failed sid=%s path=%s: %v", sid, path, err)
			_ = c.writeMsg(msgTypeFile, appendFileMsg(sid, msgTypeFileAbort, nil))
			return
		}
	}
}

func (c *Client) closeFile(sid string) {
	c.fileMu.Lock()
	ft := c.files[sid]
	delete(c.files, sid)
	c.fileMu.Unlock()
	if ft != nil && ft.file != nil {
		_ = ft.file.Close()
	}
}

func (c *Client) closeAllFiles() {
	c.fileMu.Lock()
	sids := make([]string, 0, len(c.files))
	for sid := range c.files {
		sids = append(sids, sid)
	}
	c.fileMu.Unlock()
	for _, sid := range sids {
		c.closeFile(sid)
	}
}

func appendFileMsg(sid string, typ byte, payload []byte) []byte {
	msg := make([]byte, 33+len(payload))
	copy(msg[:32], []byte(sid))
	msg[32] = typ
	copy(msg[33:], payload)
	return msg
}

func safePath(root, name string) string {
	clean := filepath.Clean("/" + name)
	return filepath.Join(root, strings.TrimPrefix(clean, "/"))
}

func (c *Client) handleHTTP(data []byte) {
	if tunnelID, direction, payload, ok := parseTunnelDataMsg(data); ok {
		if direction == 0 {
			c.handleTunnelHTTP(tunnelID, payload)
		}
		return
	}

	if tunnelID, devicePort, proto, ok := parseTunnelCreateMsg(data); ok {
		c.tunnelMu.Lock()
		c.tunnels[tunnelID] = &TunnelTarget{port: int(devicePort), proto: proto}
		c.tunnelMu.Unlock()
		log.Printf("tunnel create tunnel=%s local_port=%d proto=%s", tunnelID, devicePort, proto)
		return
	}

	if len(data) == 64 {
		tunnelID := strings.TrimRight(string(data[:64]), "\x00")
		c.tunnelMu.Lock()
		delete(c.tunnels, tunnelID)
		c.tunnelMu.Unlock()
		log.Printf("tunnel revoke tunnel=%s", tunnelID)
		return
	}

	if err := c.handleLegacyHTTPProxy(data); err != nil {
		log.Printf("http proxy failed: %v", err)
	}
}

func (c *Client) handleTunnelHTTP(tunnelID string, reqData []byte) {
	c.tunnelMu.RLock()
	target := c.tunnels[tunnelID]
	c.tunnelMu.RUnlock()

	host := "127.0.0.1"
	port := c.httpPort
	if target != nil && target.port > 0 {
		port = target.port
	}

	resp, err := proxyRawHTTPRequest(reqData, host, port)
	if err != nil {
		resp = buildHTTPError(http.StatusBadGateway, err.Error())
	}
	msg := buildTunnelDataMsg(tunnelID, 1, resp)
	_ = c.writeMsg(msgTypeHttp, msg)
}

func (c *Client) handleLegacyHTTPProxy(data []byte) error {
	offset := 0
	if len(data) >= 19 && (data[0] == 0 || data[0] == 1) {
		offset = 1
	}
	if len(data) < offset+18+6 {
		return fmt.Errorf("invalid legacy http data bytes=%d", len(data))
	}

	srcAddr := data[offset : offset+18]
	dest := data[offset+18 : offset+24]
	payload := data[offset+24:]
	ip := net.IP(dest[:4]).String()
	port := binary.BigEndian.Uint16(dest[4:6])

	resp, err := proxyRawHTTPRequest(payload, ip, int(port))
	if err != nil {
		resp = buildHTTPError(http.StatusBadGateway, err.Error())
	}

	out := append([]byte{}, srcAddr...)
	out = append(out, resp...)
	return c.writeMsg(msgTypeHttp, out)
}

func proxyRawHTTPRequest(raw []byte, host string, port int) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty http request")
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}

	resp, err := io.ReadAll(conn)
	if err != nil && len(resp) == 0 {
		return nil, err
	}
	return resp, nil
}

func buildHTTPError(status int, msg string) []byte {
	body := msg + "\n"
	return []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body))
}

func parseTunnelDataMsg(data []byte) (tunnelID string, direction byte, payload []byte, ok bool) {
	if len(data) < 69 {
		return "", 0, nil, false
	}
	tunnelID = strings.TrimRight(string(data[:64]), "\x00")
	direction = data[64]
	dataLen := binary.BigEndian.Uint32(data[65:69])
	if len(data) < 69+int(dataLen) || (direction != 0 && direction != 1) {
		return "", 0, nil, false
	}
	payload = data[69 : 69+dataLen]
	return tunnelID, direction, payload, true
}

func buildTunnelDataMsg(tunnelID string, direction byte, data []byte) []byte {
	msg := make([]byte, 64+1+4+len(data))
	copy(msg[:64], []byte(tunnelID))
	msg[64] = direction
	binary.BigEndian.PutUint32(msg[65:69], uint32(len(data)))
	copy(msg[69:], data)
	return msg
}

func parseTunnelCreateMsg(data []byte) (tunnelID string, devicePort uint16, proto string, ok bool) {
	if len(data) < 67 {
		return "", 0, "", false
	}
	tunnelID = strings.TrimRight(string(data[:64]), "\x00")
	devicePort = binary.BigEndian.Uint16(data[64:66])
	protoLen := int(data[66])
	if len(data) != 67+protoLen {
		return "", 0, "", false
	}
	proto = string(data[67 : 67+protoLen])
	return tunnelID, devicePort, proto, true
}
