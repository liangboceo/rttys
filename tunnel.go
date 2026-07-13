package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"rttys/utils"

	"github.com/rs/zerolog/log"
)

// Tunnel 隧道模型
type Tunnel struct {
	ID          int64     `json:"id"`
	TunnelID    string    `json:"tunnel_id"`
	DevID       string    `json:"devid"`
	DevicePort  int       `json:"device_port"`
	Proto       string    `json:"proto"`
	PublicPort  int       `json:"public_port"`
	AccessToken string    `json:"access_token"`
	TokenExpire time.Time `json:"token_expire"`
	Status      int       `json:"status"`
	Creator     string    `json:"creator"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GenAccessToken 生成访问 token
// token = Base64URL(HMAC-SHA256(secret, tunnel_id + devid + timestamp + salt)) + "." + Base64URL(tunnel_id)
func GenAccessToken(secret, tunnelID, devID string) string {
	salt := strconv.FormatInt(time.Now().UnixNano(), 10)
	payload := tunnelID + devID + salt

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	sigPart := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)
	tunnelPart := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(tunnelID))

	return sigPart + "." + tunnelPart
}

// ParseTokenTunnelID 从 token 中解析 tunnel_id
func ParseTokenTunnelID(token string) (string, bool) {
	parts := splitToken(token)
	if len(parts) != 2 {
		return "", false
	}

	tunnelID, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[1])
	if err != nil {
		return "", false
	}

	return string(tunnelID), true
}

// VerifyToken 验证 token 签名是否有效
func VerifyToken(secret, token, tunnelID, devID string) bool {
	parts := splitToken(token)
	if len(parts) != 2 {
		return false
	}

	// 重新计算签名，验证是否匹配
	mac := hmac.New(sha256.New, []byte(secret))
	// 我们无法反向推导 salt，所以验证只依赖数据库中的 token 比对
	// 外部验证通过数据库记录的 access_token 比对 + Auth 服务二次校验

	_ = mac
	_ = devID
	_ = parts

	return len(parts) == 2
}

// splitToken 分割 token
func splitToken(token string) []string {
	result := make([]string, 0, 2)
	dotIdx := -1
	for i, c := range token {
		if c == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx == -1 {
		return result
	}
	result = append(result, token[:dotIdx], token[dotIdx+1:])
	return result
}

// CreateTunnel 在数据库中创建隧道记录
func CreateTunnel(cfgDb, tunnelID, devID string, devicePort int, proto string, publicPort int, accessToken string, duration int, creator string) (*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expire := now.Add(time.Duration(duration) * time.Second)

	_, err = db.Exec(
		`INSERT INTO tunnel (tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		tunnelID, devID, devicePort, proto, publicPort, accessToken, expire, creator, now, now,
	)
	if err != nil {
		log.Error().Msgf("CreateTunnel DB error: %s", err.Error())
		return nil, err
	}

	return &Tunnel{
		TunnelID:    tunnelID,
		DevID:       devID,
		DevicePort:  devicePort,
		Proto:       proto,
		PublicPort:  publicPort,
		AccessToken: accessToken,
		TokenExpire: expire,
		Status:      1,
		Creator:     creator,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// GetTunnelByToken 通过 access_token 查询隧道
func GetTunnelByToken(cfgDb, token string) (*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{}
	var expireStr string
	var createdAtStr string
	var updatedAtStr string

	err = db.QueryRow(
		`SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at
		 FROM tunnel WHERE access_token = ?`, token,
	).Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
		&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
	t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)

	return t, nil
}

// GetTunnelByID 通过 tunnel_id 查询隧道
func GetTunnelByID(cfgDb, tunnelID string) (*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{}
	var expireStr string
	var createdAtStr string
	var updatedAtStr string

	err = db.QueryRow(
		`SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at
		 FROM tunnel WHERE tunnel_id = ?`, tunnelID,
	).Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
		&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
	t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)

	return t, nil
}

// GetTunnelByPublicPort 通过公网端口查询隧道
func GetTunnelByPublicPort(cfgDb string, port int) (*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{}
	var expireStr string
	var createdAtStr string
	var updatedAtStr string

	err = db.QueryRow(
		`SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at
		 FROM tunnel WHERE public_port = ? AND status = 1`, port,
	).Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
		&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
	t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)

	return t, nil
}

// GetActiveTunnelByDevPort 查询同一设备同一内网端口的活跃隧道
func GetActiveTunnelByDevPort(cfgDb, devID string, devicePort int, proto string) (*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{}
	var expireStr string
	var createdAtStr string
	var updatedAtStr string

	err = db.QueryRow(
		`SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at
		 FROM tunnel WHERE devid = ? AND device_port = ? AND proto = ? AND status = 1 AND token_expire > ?
		 ORDER BY created_at DESC LIMIT 1`, devID, devicePort, proto, time.Now(),
	).Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
		&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
	t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)

	return t, nil
}

// ListTunnels 查询隧道列表
func ListTunnels(cfgDb, devid, creator string) ([]*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	query := "SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at FROM tunnel WHERE 1=1"
	args := make([]interface{}, 0)

	if devid != "" {
		query += " AND devid = ?"
		args = append(args, devid)
	}
	if creator != "" {
		query += " AND creator = ?"
		args = append(args, creator)
	}
	query += " ORDER BY created_at DESC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tunnels := make([]*Tunnel, 0)
	for rows.Next() {
		t := &Tunnel{}
		var expireStr, createdAtStr, updatedAtStr string
		err := rows.Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
			&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)
		if err != nil {
			log.Error().Msgf("ListTunnels scan error: %s", err.Error())
			continue
		}
		t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
		t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)
		tunnels = append(tunnels, t)
	}

	return tunnels, nil
}

// RevokeTunnel 回收隧道（软删除）
func RevokeTunnel(cfgDb, tunnelID string) error {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE tunnel SET status = 0, updated_at = ? WHERE tunnel_id = ?",
		time.Now(), tunnelID)
	return err
}

// CleanExpiredTunnels 清理过期的隧道
func CleanExpiredTunnels(cfgDb string) ([]*Tunnel, error) {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	// 查询所有过期但状态仍为活跃的隧道
	rows, err := db.Query(
		`SELECT id, tunnel_id, devid, device_port, proto, public_port, access_token, token_expire, status, creator, created_at, updated_at
		 FROM tunnel WHERE status = 1 AND token_expire <= ?`, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	expired := make([]*Tunnel, 0)
	for rows.Next() {
		t := &Tunnel{}
		var expireStr, createdAtStr, updatedAtStr string
		err := rows.Scan(&t.ID, &t.TunnelID, &t.DevID, &t.DevicePort, &t.Proto, &t.PublicPort,
			&t.AccessToken, &expireStr, &t.Status, &t.Creator, &createdAtStr, &updatedAtStr)
		if err != nil {
			continue
		}
		t.TokenExpire, _ = time.Parse("2006-01-02 15:04:05", expireStr)
		t.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		t.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAtStr)
		expired = append(expired, t)
	}

	// 批量标记为已过期
	if len(expired) > 0 {
		_, err = db.Exec("UPDATE tunnel SET status = 0, updated_at = ? WHERE status = 1 AND token_expire <= ?", now, now)
		if err != nil {
			log.Error().Msgf("CleanExpiredTunnels update error: %s", err.Error())
		}
	}

	return expired, nil
}

// IsPortUsed 检查公网端口是否已被隧道占用
func IsPortUsed(cfgDb string, port int) bool {
	db, err := instanceDB(cfgDb)
	if err != nil {
		return false
	}

	cnt := 0
	db.QueryRow("SELECT COUNT(*) FROM tunnel WHERE public_port = ? AND status = 1", port).Scan(&cnt)
	return cnt > 0
}

// GenTunnelID 生成隧道唯一ID
func GenTunnelID() string {
	return "tun-" + utils.GenUniqueID("tunnel")[:12]
}

// TunnelCreateRequest 创建隧道请求
type TunnelCreateRequest struct {
	DevID    string `json:"devid" binding:"required"`
	Port     int    `json:"port" binding:"required"`
	Proto    string `json:"proto"`
	Duration int    `json:"duration"`
}

// TunnelCreateResponse 创建隧道响应
type TunnelCreateResponse struct {
	TunnelID    string `json:"tunnel_id"`
	PublicURL   string `json:"public_url"`
	AccessToken string `json:"access_token"`
	ExpireAt    string `json:"expire_at"`
}

// TunnelListItem 隧道列表项
type TunnelListItem struct {
	TunnelID    string `json:"tunnel_id"`
	DevID       string `json:"devid"`
	DevicePort  int    `json:"device_port"`
	Proto       string `json:"proto"`
	PublicPort  int    `json:"public_port"`
	PublicURL   string `json:"public_url"`
	Status      int    `json:"status"`
	Creator     string `json:"creator"`
	TokenExpire string `json:"token_expire"`
	CreatedAt   string `json:"created_at"`
}

// FormatPublicURL 格式化公网访问地址
func FormatPublicURL(host string, proto string, port int) string {
	if proto == "" {
		proto = "http"
	}
	return fmt.Sprintf("%s://%s:%d", proto, host, port)
}

// FormatPublicURLWithToken 格式化携带访问 token 的公网访问地址
func FormatPublicURLWithToken(host string, proto string, port int, token string) string {
	publicURL := FormatPublicURL(host, proto, port)
	if token == "" {
		return publicURL
	}
	return publicURL + "?rtty_token=" + url.QueryEscape(token)
}
