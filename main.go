package main

import (
	"fmt"
	"os"
	"runtime"

	"rttys/config"
	"rttys/utils"
	"rttys/version"

	xlog "rttys/log"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func initDb(cfg *config.Config) error {
	db, err := instanceDB(cfg.DB)
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS config(name VARCHAR(512) PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS account(username VARCHAR(512) PRIMARY KEY NOT NULL, password TEXT NOT NULL, admin INT NOT NULL)")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS device(id VARCHAR(512) PRIMARY KEY NOT NULL, description TEXT NOT NULL, online DATETIME NOT NULL, username TEXT NOT NULL)")
	if err != nil {
		return err
	}

	// 内网穿透隧道表
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS tunnel (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tunnel_id VARCHAR(64) UNIQUE NOT NULL,
		devid VARCHAR(128) NOT NULL,
		device_port INT NOT NULL,
		proto VARCHAR(8) DEFAULT 'http',
		public_port INT UNIQUE NOT NULL,
		access_token VARCHAR(128) UNIQUE NOT NULL,
		token_expire DATETIME NOT NULL,
		status TINYINT DEFAULT 1,
		creator VARCHAR(64) NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	return err
}

func runRttys(c *cli.Context) {
	xlog.SetPath(c.String("log"))

	if c.Bool("verbose") {
		xlog.Verbose()
	}

	cfg := config.Parse(c)

	log.Info().Msg("Go Version: " + runtime.Version())
	log.Info().Msgf("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)

	log.Info().Msg("Rttys Version: " + version.Version())

	gitCommit := version.GitCommit()
	buildTime := version.BuildTime()

	if gitCommit != "" {
		log.Info().Msg("Git Commit: " + version.GitCommit())
	}

	if buildTime != "" {
		log.Info().Msg("Build Time: " + version.BuildTime())
	}

	err := initDb(cfg)
	if err != nil {
		log.Error().Msg("Init database fail:" + err.Error())
		return
	}

	br := newBroker(cfg)
	go br.run()

	// 初始化隧道端口计数器
	InitTunnelPortCounter(cfg.TunnelPortStart)

	// 恢复已存在的活跃隧道的代理端口监听
	restoreTunnelProxies(br)

	// 启动 token 过期回收定时任务
	go startTunnelCleanupScheduler(cfg)

	//先启动接口，再启动监听，防止监听时间太长导致的接口启动不了
	listenHttpProxy(br)
	apiStart(br)
	listenDevice(br)
	select {}
}

func main() {
	defaultLogPath := "/var/log/rttys.log"
	if runtime.GOOS == "windows" {
		defaultLogPath = "rttys.log"
	}

	app := &cli.App{
		Name:    "rttys",
		Usage:   "The server side for rtty",
		Version: version.Version(),
		Commands: []*cli.Command{
			{
				Name:  "run",
				Usage: "Run rttys",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "log",
						Value: defaultLogPath,
						Usage: "log file path",
					},
					&cli.StringFlag{
						Name:    "conf",
						Aliases: []string{"c"},
						Value:   "./rttys.conf",
						Usage:   "config file to load",
					},
					&cli.StringFlag{
						Name:  "addr-dev",
						Value: ":5912",
						Usage: "address to listen device",
					},
					&cli.StringFlag{
						Name:  "addr-user",
						Value: ":5913",
						Usage: "address to listen user",
					},
					&cli.StringFlag{
						Name:  "addr-http-proxy",
						Value: "",
						Usage: "address to listen for HTTP proxy (default auto)",
					},
					&cli.StringFlag{
						Name:  "http-proxy-redir-url",
						Value: "",
						Usage: "url to redirect for HTTP proxy",
					},
					&cli.StringFlag{
						Name:  "ssl-cert",
						Value: "",
						Usage: "ssl cert file Path",
					},
					&cli.StringFlag{
						Name:  "ssl-key",
						Value: "",
						Usage: "ssl key file Path",
					},
					&cli.StringFlag{
						Name:  "ssl-cacert",
						Value: "",
						Usage: "mtls CA storage in PEM file Path",
					},
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Value:   "",
						Usage:   "token to use",
					},
					&cli.StringFlag{
						Name:  "white-list",
						Value: "",
						Usage: "white list(device IDs separated by spaces or *)",
					},
					&cli.StringFlag{
						Name:  "db",
						Value: "sqlite://rttys.db",
						Usage: "database source",
					},
					&cli.BoolFlag{
						Name:  "local-auth",
						Usage: "need auth for local",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"V"},
						Usage:   "more detailed output",
					},
					// 内网穿透隧道配置
					&cli.StringFlag{
						Name:  "tunnel-port-range",
						Value: "20000-21000",
						Usage: "port range for tunnel proxy",
					},
					&cli.StringFlag{
						Name:  "auth-service-url",
						Value: "",
						Usage: "Auth service URL for SSO verification",
					},
					&cli.BoolFlag{
						Name:  "sso-enabled",
						Usage: "enable SSO authentication",
					},
					&cli.StringFlag{
						Name:  "tunnel-token-secret",
						Value: "",
						Usage: "secret key for tunnel token signing",
					},
					&cli.IntFlag{
						Name:  "default-token-duration",
						Value: 3600,
						Usage: "default tunnel token duration in seconds",
					},
				},
				Action: func(c *cli.Context) error {
					runRttys(c)
					return nil
				},
			},
			{
				Name:  "token",
				Usage: "Generate a token",
				Action: func(c *cli.Context) error {
					utils.GenToken()
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			c.App.Command("run").Run(c)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
