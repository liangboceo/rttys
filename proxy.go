package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"rttys/client"
	"rttys/config"
	"rttys/utils"

	"github.com/rs/zerolog/log"
)

// tunnelProxyConn 管理单个隧道代理连接
type tunnelProxyConn struct {
	streamID  string
	tunnelID  string
	devID     string
	conn      net.Conn
	createdAt time.Time
}

// tunnelProxyPool 隧道代理连接池
var (
	tunnelProxyConns   sync.Map // streamID -> *tunnelProxyConn
	tunnelProxyServers sync.Map // port(int) -> net.Listener
)

var tunnelPortAllocMu sync.Mutex

// InitTunnelPortCounter 保留启动初始化入口，端口分配改为扫描端口池以支持回收复用
func InitTunnelPortCounter(startPort int) {
}

// AllocatePort 分配一个可用的公网代理端口
// 从端口范围起始位置顺序扫描，已回收或过期的端口会被重新利用
func AllocatePort(cfgDb string, startPort, endPort int) (int, error) {
	tunnelPortAllocMu.Lock()
	defer tunnelPortAllocMu.Unlock()

	for candidate := startPort; candidate <= endPort; candidate++ {
		// 检查数据库中是否已被活跃隧道占用
		if IsPortUsed(cfgDb, candidate) {
			continue
		}

		// 探测端口是否空闲
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", candidate))
		if err == nil {
			ln.Close()
			return candidate, nil
		}
	}

	return 0, fmt.Errorf("no available port in range %d-%d", startPort, endPort)
}

// StartTunnelProxyServer 启动单个端口的隧道代理服务器
func StartTunnelProxyServer(br *broker, port int, tunnelID string) error {
	if _, ok := tunnelProxyServers.Load(port); ok {
		return nil
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}

	if existing, loaded := tunnelProxyServers.LoadOrStore(port, ln); loaded {
		ln.Close()
		if existing != nil {
			return nil
		}
	}

	log.Info().Msgf("Tunnel proxy listening on port %d for tunnel %s", port, tunnelID)

	go func() {
		defer func() {
			ln.Close()
			utils.ErrorHandle()
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Error().Msgf("Tunnel proxy accept error on port %d: %s", port, err)
				continue
			}

			go handleTunnelProxyConn(br, conn, port)
		}
	}()

	return nil
}

// EnsureTunnelProxyServer 确保指定隧道端口存在监听，已存在则直接复用
func EnsureTunnelProxyServer(br *broker, port int, tunnelID string) error {
	return StartTunnelProxyServer(br, port, tunnelID)
}

// StopTunnelProxyServer 停止指定端口的隧道代理服务器
func StopTunnelProxyServer(port int) {
	if ln, ok := tunnelProxyServers.Load(port); ok {
		ln.(net.Listener).Close()
		tunnelProxyServers.Delete(port)
		log.Info().Msgf("Tunnel proxy stopped on port %d", port)
	}
}

// handleTunnelProxyConn 处理隧道代理连接
func handleTunnelProxyConn(br *broker, conn net.Conn, publicPort int) {
	defer func() {
		conn.Close()
		utils.ErrorHandle()
	}()

	cfg := br.cfg

	// 通过端口查询隧道信息
	tunnel, err := GetTunnelByPublicPort(cfg.DB, publicPort)
	if err != nil || tunnel == nil {
		log.Error().Msgf("No active tunnel found for port %d", publicPort)
		return
	}

	// 检查设备是否在线
	dev, ok := br.devices[tunnel.DevID]
	if !ok {
		log.Error().Msgf("Device %s is offline for tunnel %s", tunnel.DevID, tunnel.TunnelID)
		return
	}

	// 读取 HTTP 请求
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Error().Msgf("Failed to read HTTP request on port %d: %s", publicPort, err)
		return
	}

	// 验证 token
	valid := validateProxyToken(cfg, tunnel, req)
	if !valid {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/plain")
		resp.Body = io.NopCloser(strings.NewReader("Forbidden: invalid or expired token"))
		_ = resp.Write(conn)
		return
	}

	if shouldRedirectTunnelToken(req) {
		redirectTunnelToken(conn, tunnel, req)
		return
	}

	// 生成流ID
	streamID := utils.GenUniqueID("tun-stream")

	tpc := &tunnelProxyConn{
		streamID:  streamID,
		tunnelID:  tunnel.TunnelID,
		devID:     tunnel.DevID,
		conn:      conn,
		createdAt: time.Now(),
	}

	tunnelProxyConns.Store(streamID, tpc)
	defer tunnelProxyConns.Delete(streamID)

	// 序列化 HTTP 请求并发送到设备
	requestData := serializeHTTPRequest(req)

	// 构造隧道数据消息发送给设备
	msg := buildTunnelDataMsg(tunnel.TunnelID, 0, requestData) // direction=0 表示请求
	br.httpReq <- &httpReq{tunnel.DevID, msg}

	log.Info().Msgf("Tunnel proxy: stream=%s tunnel=%s dev=%s port=%d", streamID, tunnel.TunnelID, tunnel.DevID, publicPort)

	// 等待设备响应数据，写入客户端
	// 响应通过 broker 的 tunnelDataResp 通道返回
	// 这里启动一个等待协程

	// 如果是 WebSocket 升级请求或需要双向通信，进入长连接模式
	if req.Header.Get("Upgrade") == "websocket" {
		handleTunnelWebSocket(br, tpc, dev, tunnel, reader)
	} else {
		handleTunnelHTTP(br, tpc, dev, tunnel, reader)
	}
}

// handleTunnelHTTP 处理普通 HTTP 隧道代理请求-响应
func handleTunnelHTTP(br *broker, tpc *tunnelProxyConn, dev client.Client, tunnel *Tunnel, reader *bufio.Reader) {
	// 对于普通 HTTP 请求，读取后续请求（HTTP/1.1 keep-alive）
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		requestData := serializeHTTPRequest(req)
		msg := buildTunnelDataMsg(tunnel.TunnelID, 0, requestData)
		br.httpReq <- &httpReq{tunnel.DevID, msg}
	}
}

// handleTunnelWebSocket 处理 WebSocket 隧道代理
func handleTunnelWebSocket(br *broker, tpc *tunnelProxyConn, dev client.Client, tunnel *Tunnel, reader *bufio.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := tpc.conn.Read(buf)
		if err != nil {
			return
		}
		msg := buildTunnelDataMsg(tunnel.TunnelID, 0, buf[:n])
		br.httpReq <- &httpReq{tunnel.DevID, msg}
	}
}

func tunnelAuthCookieName(tunnelID string) string {
	return "rtty_tunnel_token_" + strings.NewReplacer("-", "_", ".", "_").Replace(tunnelID)
}

func shouldRedirectTunnelToken(req *http.Request) bool {
	return req.URL.Query().Get("rtty_token") != ""
}

func redirectTunnelToken(conn net.Conn, tunnel *Tunnel, req *http.Request) {
	query := req.URL.Query()
	query.Del("rtty_token")
	location := req.URL.Path
	if encodedQuery := query.Encode(); encodedQuery != "" {
		location += "?" + encodedQuery
	}
	if req.URL.RawFragment != "" {
		location += "#" + req.URL.RawFragment
	}

	resp := &http.Response{
		StatusCode: http.StatusFound,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header.Set("Location", location)
	resp.Header.Add("Set-Cookie", (&http.Cookie{
		Name:     tunnelAuthCookieName(tunnel.TunnelID),
		Value:    tunnel.AccessToken,
		Path:     "/",
		Expires:  tunnel.TokenExpire,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}).String())
	resp.Body = io.NopCloser(strings.NewReader(""))
	_ = resp.Write(conn)
}

// validateProxyToken 验证代理请求中的 token
func validateProxyToken(cfg *config.Config, tunnel *Tunnel, req *http.Request) bool {
	// 检查隧道状态和过期时间
	if tunnel.Status != 1 || time.Now().After(tunnel.TokenExpire) {
		return false
	}

	// 方式一：从 URL Path 中提取 /proxy/{token}/...
	token := ""
	path := req.URL.Path
	if strings.HasPrefix(path, "/proxy/") {
		parts := strings.SplitN(strings.TrimPrefix(path, "/proxy/"), "/", 2)
		if len(parts) >= 1 {
			token = parts[0]
			// 重写 URL Path
			if len(parts) > 1 {
				req.URL.Path = "/" + parts[1]
			} else {
				req.URL.Path = "/"
			}
		}
	}

	// 方式二：从 Authorization Header 中提取
	if token == "" {
		auth := req.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// 方式三：从 Query String 中提取
	if token == "" {
		token = req.URL.Query().Get("rtty_token")
	}

	// 方式四：从首次入口写入的 Cookie 中提取，兼容静态资源等后续请求不带 query token 的场景
	if token == "" {
		if cookie, err := req.Cookie(tunnelAuthCookieName(tunnel.TunnelID)); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return false
	}

	// 验证 token 是否匹配
	if token != tunnel.AccessToken {
		log.Error().Msgf("validateProxyToken: token mismatch for tunnel %s", tunnel.TunnelID)
		return false
	}

	return true
}

// serializeHTTPRequest 将 HTTP 请求序列化为字节数组
func serializeHTTPRequest(req *http.Request) []byte {
	// 构造简化的 HTTP 请求数据
	var sb strings.Builder

	// Request line
	sb.WriteString(fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto))

	// Host header
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", req.Host))

	// Other headers
	for key, values := range req.Header {
		for _, val := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, val))
		}
	}
	sb.WriteString("\r\n")

	headerBytes := []byte(sb.String())

	// 如果有 body，追加 body
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil && len(bodyBytes) > 0 {
			result := make([]byte, len(headerBytes)+len(bodyBytes))
			copy(result, headerBytes)
			copy(result[len(headerBytes):], bodyBytes)
			return result
		}
	}

	return headerBytes
}

// buildTunnelDataMsg 构造隧道数据消息
// tunnel_id(64B) + direction(1B, 0=请求 1=响应) + data_len(4B big-endian) + data(N bytes)
func buildTunnelDataMsg(tunnelID string, direction byte, data []byte) []byte {
	msg := make([]byte, 64+1+4+len(data))

	// tunnel_id (64 bytes)
	tidBytes := []byte(tunnelID)
	copy(msg[:64], tidBytes)

	// direction (1 byte)
	msg[64] = direction

	// data_len (4 bytes big-endian)
	binary.BigEndian.PutUint32(msg[65:69], uint32(len(data)))

	// data
	copy(msg[69:], data)

	return msg
}

// parseTunnelDataMsg 解析隧道数据消息
func parseTunnelDataMsg(data []byte) (tunnelID string, direction byte, payload []byte, ok bool) {
	if len(data) < 69 {
		return "", 0, nil, false
	}

	tunnelID = strings.TrimRight(string(data[:64]), "\x00")
	direction = data[64]
	dataLen := binary.BigEndian.Uint32(data[65:69])

	if len(data) < 69+int(dataLen) {
		return "", 0, nil, false
	}

	payload = data[69 : 69+dataLen]
	ok = true
	return
}

// buildTunnelCreateMsg 构造隧道建立消息
// tunnel_id(64B) + device_port(2B big-endian) + proto_len(1B) + proto(N bytes)
func buildTunnelCreateMsg(tunnelID string, devicePort int, proto string) []byte {
	protoBytes := []byte(proto)
	msg := make([]byte, 64+2+1+len(protoBytes))

	copy(msg[:64], []byte(tunnelID))
	binary.BigEndian.PutUint16(msg[64:66], uint16(devicePort))
	msg[66] = byte(len(protoBytes))
	copy(msg[67:], protoBytes)

	return msg
}

// buildTunnelRevokeMsg 构造隧道回收消息
// tunnel_id(64B)
func buildTunnelRevokeMsg(tunnelID string) []byte {
	msg := make([]byte, 64)
	copy(msg, []byte(tunnelID))
	return msg
}

// startTunnelCleanupScheduler 启动隧道过期清理定时任务
func startTunnelCleanupScheduler(cfg *config.Config) {
	defer utils.ErrorHandle()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Info().Msg("Tunnel cleanup scheduler started")

	for range ticker.C {
		expired, err := CleanExpiredTunnels(cfg.DB)
		if err != nil {
			log.Error().Msgf("Tunnel cleanup error: %s", err.Error())
			continue
		}

		for _, t := range expired {
			log.Info().Msgf("Tunnel expired, cleaning up: %s (port %d)", t.TunnelID, t.PublicPort)
			StopTunnelProxyServer(t.PublicPort)

			// 通知设备回收隧道
			if br := getGlobalBroker(); br != nil {
				if _, ok := br.devices[t.DevID]; ok {
					revokeMsg := buildTunnelRevokeMsg(t.TunnelID)
					br.httpReq <- &httpReq{t.DevID, revokeMsg}
				}
			}

			// 清理代理连接
			tunnelProxyConns.Range(func(key, value interface{}) bool {
				tpc := value.(*tunnelProxyConn)
				if tpc.tunnelID == t.TunnelID {
					tpc.conn.Close()
					tunnelProxyConns.Delete(key)
				}
				return true
			})
		}

		if len(expired) > 0 {
			log.Info().Msgf("Cleaned up %d expired tunnels", len(expired))
		}
	}
}

// globalBroker 全局 broker 引用，供定时任务使用
var globalBroker *broker

func getGlobalBroker() *broker {
	return globalBroker
}

// restoreTunnelProxies 恢复已存在的活跃隧道的代理端口监听
func restoreTunnelProxies(br *broker) {
	globalBroker = br
	cfg := br.cfg

	tunnels, err := ListTunnels(cfg.DB, "", "")
	if err != nil {
		log.Error().Msgf("Failed to restore tunnel proxies: %s", err.Error())
		return
	}

	for _, t := range tunnels {
		if t.Status != 1 {
			continue
		}

		if time.Now().After(t.TokenExpire) {
			_ = RevokeTunnel(cfg.DB, t.TunnelID)
			continue
		}

		if _, ok := br.devices[t.DevID]; !ok {
			if err := DeleteTunnel(cfg.DB, t.TunnelID); err != nil {
				log.Error().Msgf("Failed to delete offline tunnel %s for device %s: %s", t.TunnelID, t.DevID, err.Error())
				continue
			}
			log.Info().Msgf("Deleted offline tunnel %s for device %s on port %d", t.TunnelID, t.DevID, t.PublicPort)
			continue
		}

		// 恢复代理端口监听，不存在则启动，已存在则复用
		err := EnsureTunnelProxyServer(br, t.PublicPort, t.TunnelID)
		if err != nil {
			log.Error().Msgf("Failed to restore proxy for tunnel %s on port %d: %s",
				t.TunnelID, t.PublicPort, err.Error())
		}
	}
}
