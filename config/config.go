package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/kylelemons/go-gypsy/yaml"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

// Config struct
type Config struct {
	AddrDev           string
	AddrUser          string
	AddrHttpProxy     string
	HttpProxyRedirURL string
	HttpProxyPort     int
	SslCert           string
	SslKey            string
	SslCacert         string // mTLS for device
	Token             string
	WhiteList         map[string]bool
	DB                string
	LocalAuth         bool

	// 内网穿透隧道配置
	TunnelPortRange      string // 公网代理端口范围，如 "20000-21000"
	TunnelPortStart      int    // 起始端口
	TunnelPortEnd        int    // 结束端口
	AuthServiceURL       string // Auth 服务地址
	SSOEnabled           bool   // 是否启用 SSO
	TunnelTokenSecret    string // 隧道 token 签名密钥
	DefaultTokenDuration int    // 默认 token 有效期（秒）
	PublicIP             string // 配置的公网 IP，优先使用
}

func getConfigOpt(yamlCfg *yaml.File, name string, opt interface{}) {
	val, err := yamlCfg.Get(name)
	if err != nil {
		return
	}

	switch opt := opt.(type) {
	case *string:
		*opt = val
	case *int:
		*opt, _ = strconv.Atoi(val)
	case *bool:
		*opt, _ = strconv.ParseBool(val)

	}
}

// Parse config
func Parse(c *cli.Context) *Config {
	cfg := &Config{
		AddrDev:           c.String("addr-dev"),
		AddrUser:          c.String("addr-user"),
		AddrHttpProxy:     c.String("addr-http-proxy"),
		HttpProxyRedirURL: c.String("http-proxy-redir-url"),
		SslCert:           c.String("ssl-cert"),
		SslKey:            c.String("ssl-key"),
		SslCacert:         c.String("ssl-cacert"),
		Token:             c.String("token"),
		DB:                c.String("db"),
		LocalAuth:         c.Bool("local-auth"),
	}

	cfg.WhiteList = make(map[string]bool)

	whiteList := c.String("white-list")

	if whiteList == "*" {
		cfg.WhiteList = nil
	} else {
		for _, id := range strings.Fields(whiteList) {
			cfg.WhiteList[id] = true
		}
	}

	yamlCfg, err := yaml.ReadFile(c.String("conf"))
	if err == nil {
		getConfigOpt(yamlCfg, "addr-dev", &cfg.AddrDev)
		getConfigOpt(yamlCfg, "addr-user", &cfg.AddrUser)
		getConfigOpt(yamlCfg, "addr-http-proxy", &cfg.AddrHttpProxy)
		getConfigOpt(yamlCfg, "http-proxy-redir-url", &cfg.HttpProxyRedirURL)
		getConfigOpt(yamlCfg, "ssl-cert", &cfg.SslCert)
		getConfigOpt(yamlCfg, "ssl-key", &cfg.SslKey)
		getConfigOpt(yamlCfg, "ssl-cacert", &cfg.SslCacert)
		getConfigOpt(yamlCfg, "token", &cfg.Token)
		getConfigOpt(yamlCfg, "db", &cfg.DB)
		getConfigOpt(yamlCfg, "local-auth", &cfg.LocalAuth)

		// 隧道配置
		getConfigOpt(yamlCfg, "tunnel-port-range", &cfg.TunnelPortRange)
		getConfigOpt(yamlCfg, "auth-service-url", &cfg.AuthServiceURL)
		getConfigOpt(yamlCfg, "sso-enabled", &cfg.SSOEnabled)
		getConfigOpt(yamlCfg, "tunnel-token-secret", &cfg.TunnelTokenSecret)
		getConfigOpt(yamlCfg, "default-token-duration", &cfg.DefaultTokenDuration)
		getConfigOpt(yamlCfg, "public-ip", &cfg.PublicIP)

		val, err := yamlCfg.Get("white-list")
		if err == nil {
			if val == "*" || val == "\"*\"" {
				cfg.WhiteList = nil
			} else {
				for _, id := range strings.Fields(val) {
					cfg.WhiteList[id] = true
				}
			}
		}
	}

	// 解析端口范围
	if cfg.TunnelPortRange == "" {
		cfg.TunnelPortRange = "20000-21000"
	}
	ports := strings.Split(cfg.TunnelPortRange, "-")
	if len(ports) == 2 {
		cfg.TunnelPortStart, _ = strconv.Atoi(strings.TrimSpace(ports[0]))
		cfg.TunnelPortEnd, _ = strconv.Atoi(strings.TrimSpace(ports[1]))
	}
	if cfg.TunnelPortStart <= 0 {
		cfg.TunnelPortStart = 20000
	}
	if cfg.TunnelPortEnd <= cfg.TunnelPortStart {
		cfg.TunnelPortEnd = 21000
	}

	// 默认 token 有效期
	if cfg.DefaultTokenDuration <= 0 {
		cfg.DefaultTokenDuration = 3600
	}

	// 默认 token 签名密钥
	if cfg.TunnelTokenSecret == "" {
		cfg.TunnelTokenSecret = "rttys-default-tunnel-secret-change-me"
	}

	if cfg.SslCert != "" && cfg.SslKey != "" {
		_, err := os.Lstat(cfg.SslCert)
		if err != nil {
			log.Error().Msg(err.Error())
			cfg.SslCert = ""
		}

		_, err = os.Lstat(cfg.SslKey)
		if err != nil {
			log.Error().Msg(err.Error())
			cfg.SslKey = ""
		}
	}

	return cfg
}
