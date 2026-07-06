package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"rttys/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// SSOAuthRequest SSO 认证请求
type SSOAuthRequest struct {
	SSOToken string `json:"sso_token" binding:"required"`
}

// handleSSOAuth 处理 SSO 登录桥接
// 慧析平台在用户 SSO 登录后，携带平台签发的 SSO token 调用此接口
func handleSSOAuth(br *broker, c *gin.Context) {
	cfg := br.cfg

	if !cfg.SSOEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "SSO not enabled"})
		return
	}

	var req SSOAuthRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "invalid request"})
		return
	}

	// 如果配置了 Auth 服务地址，将 SSO token 转发至 Auth 服务验证
	if cfg.AuthServiceURL != "" {
		valid := verifySSOTokenWithAuthService(cfg.AuthServiceURL, req.SSOToken)
		if !valid {
			c.JSON(http.StatusForbidden, gin.H{"code": -1, "msg": "SSO token verification failed"})
			return
		}
	}

	// 生成 sid 并设置 Cookie（与现有 httpAuth 机制兼容）
	sid := utils.GenUniqueID("sso")
	httpSessions.Set(sid, "sso-user", 30*time.Minute)

	c.SetCookie("sid", sid, 0, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"sid":      sid,
			"username": "sso-user",
		},
	})
}

// verifySSOTokenWithAuthService 调用 Auth 服务验证 SSO token
func verifySSOTokenWithAuthService(authServiceURL, ssoToken string) bool {
	// 构造验证请求
	client := &http.Client{Timeout: 5 * time.Second}
	body := fmt.Sprintf(`{"token":"%s"}`, ssoToken)
	resp, err := client.Post(
		strings.TrimRight(authServiceURL, "/")+"/auth/verify",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		log.Error().Msgf("Auth service verify error: %s", err.Error())
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// handleTunnelCreate 创建隧道
// POST /api/tunnel/create
//
//	{
//	  "devid": "device-001",
//	  "port": 8080,
//	  "proto": "http",
//	  "duration": 3600
//	}
func handleTunnelCreate(br *broker, c *gin.Context) {
	cfg := br.cfg
	allowOrigin(c.Writer)

	var req TunnelCreateRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "invalid request"})
		return
	}

	if req.Proto == "" {
		req.Proto = "http"
	}
	if req.Duration <= 0 {
		req.Duration = cfg.DefaultTokenDuration
	}

	// 检查设备是否在线
	_, ok := br.devices[req.DevID]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "device offline"})
		return
	}

	// 分配公网端口
	publicPort, err := AllocatePort(cfg.DB, cfg.TunnelPortStart, cfg.TunnelPortEnd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "msg": "no available port"})
		return
	}

	// 生成隧道 ID 和访问 Token
	tunnelID := GenTunnelID()
	accessToken := GenAccessToken(cfg.TunnelTokenSecret, tunnelID, req.DevID)

	// 获取创建者用户名
	creator := getLoginUsername(c)

	// 持久化隧道记录
	tunnel, err := CreateTunnel(cfg.DB, tunnelID, req.DevID, req.Port, req.Proto, publicPort, accessToken, req.Duration, creator)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "msg": "failed to create tunnel"})
		return
	}

	// 启动代理端口监听
	createMsg := buildTunnelCreateMsg(tunnelID, req.Port, req.Proto)
	br.httpReq <- &httpReq{req.DevID, createMsg}
	log.Info().Msgf("Tunnel create msg sent to device %s: tunnel=%s port=%d", req.DevID, tunnelID, req.Port)

	// 启动代理服务器
	err = StartTunnelProxyServer(br, publicPort, tunnelID)
	if err != nil {
		// 启动失败，回收隧道
		RevokeTunnel(cfg.DB, tunnelID)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "msg": "failed to start proxy server"})
		return
	}

	// 获取公网 IP
	publicIP := getPublicIP(c)

	resp := TunnelCreateResponse{
		TunnelID:    tunnel.TunnelID,
		PublicURL:   FormatPublicURL(publicIP, req.Proto, publicPort),
		AccessToken: tunnel.AccessToken,
		ExpireAt:    tunnel.TokenExpire.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": resp})
}

// handleTunnelDelete 删除/回收隧道
// POST /api/tunnel/delete
// { "tunnel_id": "tun-xxx" }
func handleTunnelDelete(br *broker, c *gin.Context) {
	cfg := br.cfg
	allowOrigin(c.Writer)

	type deleteReq struct {
		TunnelID string `json:"tunnel_id" binding:"required"`
	}

	var req deleteReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "msg": "invalid request"})
		return
	}

	// 查询隧道信息
	tunnel, err := GetTunnelByID(cfg.DB, req.TunnelID)
	if err != nil || tunnel == nil {
		c.JSON(http.StatusNotFound, gin.H{"code": -1, "msg": "tunnel not found"})
		return
	}

	// 回收隧道（软删除）
	if err := RevokeTunnel(cfg.DB, req.TunnelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "msg": "failed to revoke tunnel"})
		return
	}

	// 停止代理端口监听
	StopTunnelProxyServer(tunnel.PublicPort)

	// 通知设备回收隧道
	revokeMsg := buildTunnelRevokeMsg(tunnel.TunnelID)
	br.httpReq <- &httpReq{tunnel.DevID, revokeMsg}
	log.Info().Msgf("Tunnel revoke msg sent to device %s: tunnel=%s", tunnel.DevID, tunnel.TunnelID)

	// 清理相关代理连接
	tunnelProxyConns.Range(func(key, value interface{}) bool {
		tpc := value.(*tunnelProxyConn)
		if tpc.tunnelID == tunnel.TunnelID {
			tpc.conn.Close()
			tunnelProxyConns.Delete(key)
		}
		return true
	})

	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok"})
}

// handleTunnelList 查询隧道列表
// GET /api/tunnel/list?devid=xxx
func handleTunnelList(br *broker, c *gin.Context) {
	cfg := br.cfg
	allowOrigin(c.Writer)

	devid := c.Query("devid")
	creator := ""
	username := getLoginUsername(c)

	// 非管理员只能查看自己创建的隧道
	if username != "" && !isAdminUsername(cfg, username) {
		creator = username
	}

	tunnels, err := ListTunnels(cfg.DB, devid, creator)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "msg": "failed to list tunnels"})
		return
	}

	publicIP := getPublicIP(c)

	list := make([]TunnelListItem, 0, len(tunnels))
	for _, t := range tunnels {
		item := TunnelListItem{
			TunnelID:    t.TunnelID,
			DevID:       t.DevID,
			DevicePort:  t.DevicePort,
			Proto:       t.Proto,
			PublicPort:  t.PublicPort,
			PublicURL:   FormatPublicURL(publicIP, t.Proto, t.PublicPort),
			Status:      t.Status,
			Creator:     t.Creator,
			TokenExpire: t.TokenExpire.Format(time.RFC3339),
			CreatedAt:   t.CreatedAt.Format(time.RFC3339),
		}

		// 如果 token 已过期但状态仍为活跃，标记状态
		if t.Status == 1 && time.Now().After(t.TokenExpire) {
			item.Status = 0
		}

		list = append(list, item)
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": list})
}

// handleTunnelDetail 查询单个隧道详情
// GET /api/tunnel/:id
func handleTunnelDetail(br *broker, c *gin.Context) {
	cfg := br.cfg
	allowOrigin(c.Writer)

	tunnelID := c.Param("id")
	tunnel, err := GetTunnelByID(cfg.DB, tunnelID)
	if err != nil || tunnel == nil {
		c.JSON(http.StatusNotFound, gin.H{"code": -1, "msg": "tunnel not found"})
		return
	}

	publicIP := getPublicIP(c)

	item := TunnelListItem{
		TunnelID:    tunnel.TunnelID,
		DevID:       tunnel.DevID,
		DevicePort:  tunnel.DevicePort,
		Proto:       tunnel.Proto,
		PublicPort:  tunnel.PublicPort,
		PublicURL:   FormatPublicURL(publicIP, tunnel.Proto, tunnel.PublicPort),
		Status:      tunnel.Status,
		Creator:     tunnel.Creator,
		TokenExpire: tunnel.TokenExpire.Format(time.RFC3339),
		CreatedAt:   tunnel.CreatedAt.Format(time.RFC3339),
	}

	if tunnel.Status == 1 && time.Now().After(tunnel.TokenExpire) {
		item.Status = 0
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": item})
}

// handleTokenProxy 处理 /proxy/:token/*path 路由（主服务上的代理路由，兼容方案）
func handleTokenProxy(br *broker, c *gin.Context) {
	cfg := br.cfg

	token := c.Param("token")
	path := c.Param("path")

	// 从 token 中解析 tunnel_id 并查询隧道
	tunnel, err := GetTunnelByToken(cfg.DB, token)
	if err != nil || tunnel == nil {
		c.JSON(http.StatusForbidden, gin.H{"code": -1, "msg": "invalid token"})
		return
	}

	// 检查隧道状态
	if tunnel.Status != 1 || time.Now().After(tunnel.TokenExpire) {
		c.JSON(http.StatusForbidden, gin.H{"code": -1, "msg": "tunnel expired"})
		return
	}

	// 检查设备是否在线
	_, ok := br.devices[tunnel.DevID]
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": -1, "msg": "device offline"})
		return
	}

	// 构造并发送隧道数据请求到设备
	requestLine := fmt.Sprintf("%s %s %s\r\n", c.Request.Method, path, c.Request.Proto)
	headerStr := formatHTTPHeaders(c.Request)

	bodyBytes, _ := io.ReadAll(c.Request.Body)
	requestData := append([]byte(requestLine+headerStr+"\r\n"), bodyBytes...)

	msg := buildTunnelDataMsg(tunnel.TunnelID, 0, requestData) // direction=0 表示请求
	br.httpReq <- &httpReq{tunnel.DevID, msg}

	// 设置超时等待响应
	timeout := time.After(30 * time.Second)

	// 注册临时响应通道
	respCh := make(chan []byte, 1)
	tempStreamID := utils.GenUniqueID("token-proxy")
	tpc := &tunnelProxyConn{
		streamID:  tempStreamID,
		tunnelID:  tunnel.TunnelID,
		devID:     tunnel.DevID,
		conn:      nil, // 无长连接
		createdAt: time.Now(),
	}
	tunnelProxyConns.Store(tempStreamID, tpc)
	defer tunnelProxyConns.Delete(tempStreamID)

	// 轮询等待响应
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			c.JSON(http.StatusGatewayTimeout, gin.H{"code": -1, "msg": "timeout"})
			return
		case respData := <-respCh:
			c.Data(http.StatusOK, "application/octet-stream", respData)
			return
		case <-ticker.C:
			// 检查 tunnelProxyConns 中是否有此流的数据
			continue
		}
	}
}

// formatHTTPHeaders 格式化 HTTP 头
func formatHTTPHeaders(req *http.Request) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", req.Host))
	for key, values := range req.Header {
		if key == "Host" {
			continue
		}
		for _, val := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", key, val))
		}
	}
	return sb.String()
}

// getPublicIP 获取公网 IP 地址
func getPublicIP(c *gin.Context) string {
	host, _, err := net.SplitHostPort(c.Request.Host)
	if err != nil {
		host = c.Request.Host
	}

	// 如果是 loopback 地址，尝试获取实际 IP
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		// 获取本机非 loopback IP
		addrs, err := net.InterfaceAddrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return ipnet.IP.String()
					}
				}
			}
		}
		return "127.0.0.1"
	}

	return host
}
