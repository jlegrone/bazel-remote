package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	auth "github.com/abbot/go-http-auth"
	"github.com/buchgr/bazel-remote/cache"
	"github.com/buchgr/bazel-remote/cache/proxy"
	"github.com/buchgr/bazel-remote/server"
	"github.com/urfave/cli"
	yaml "gopkg.in/yaml.v2"
)

// Config provides the configuration
type Config struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Dir                string `yaml:"dir"`
	MaxSize            int    `yaml:"max_size"`
	HtpasswdFile       string `yaml:"htpasswd_file"`
	TLSCertFile        string `yaml:"tls_cert_file"`
	TLSKeyFile         string `yaml:"tls_key_file"`
	GoogleCloudStorage *struct {
		Bucket                string `yaml:"bucket"`
		UseDefaultCredentials bool   `yaml:"use_default_credentials"`
		JSONCredentialsFile   string `yaml:"json_credentials_file"`
	} `yaml:"gcs_proxy"`
	HTTPBackend *struct {
		BaseURL string `yaml:"base_url"`
	} `yaml:"http_proxy"`
}

func parseConfig(ctx *cli.Context) (*Config, error) {
	configFile := ctx.String("config_file")
	dir := ctx.String("dir")
	maxSize := ctx.Int("max_size")
	host := ctx.String("host")
	port := ctx.Int("port")
	htpasswdFile := ctx.String("htpasswd_file")
	tlsCertFile := ctx.String("tls_cert_file")
	tlsKeyFile := ctx.String("tls_key_file")

	if configFile != "" {
		file, err := os.Open(configFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to open config file '%s': %v", configFile, err)
		}
		defer file.Close()

		data, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("Failed to read config file '%s': %v", configFile, err)
		}

		c := Config{}
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse config file '%s': %v", configFile, err)
		}

		if c.Dir == "" {
			return nil, fmt.Errorf("The 'dir' key is required in the YAML config %v", c)
		}

		if c.MaxSize == 0 {
			return nil, fmt.Errorf("The 'max_size' key is required in the YAML config")
		}

		if (c.TLSCertFile != "" && c.TLSKeyFile == "") || (c.TLSCertFile == "" && c.TLSKeyFile != "") {
			return nil, fmt.Errorf("When enabling TLS, one must specify both keys " +
				"'tls_key_file' and 'tls_cert_file' in the YAML config")
		}

		return &c, nil
	}

	if dir == "" {
		return nil, fmt.Errorf("The 'dir' flag is required")
	}

	if maxSize < 0 {
		return nil, fmt.Errorf("The 'max_size' flag is required")
	}

	if (tlsCertFile != "" && tlsKeyFile == "") || (tlsCertFile == "" && tlsKeyFile != "") {
		return nil, fmt.Errorf("When enabling TLS, one must specify both flags " +
			"'tls_key_file' and 'tls_cert_file'")
	}

	return &Config{
		Host:               host,
		Port:               port,
		Dir:                dir,
		MaxSize:            maxSize,
		HtpasswdFile:       htpasswdFile,
		TLSCertFile:        tlsCertFile,
		TLSKeyFile:         tlsKeyFile,
		GoogleCloudStorage: nil,
		HTTPBackend:        nil,
	}, nil
}

func main() {
	app := cli.NewApp()
	app.Description = "A remote build cache for Bazel."
	app.Usage = "A remote build cache for Bazel"
	app.HideHelp = true
	app.HideVersion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config_file",
			Value: "",
			Usage: "Path to a YAML configuration file. If this flag is specified then all other flags " +
				"are ignored.",
			EnvVar: "BAZEL_REMOTE_CONFIG_FILE",
		},
		cli.StringFlag{
			Name:   "dir",
			Value:  "",
			Usage:  "Directory path where to store the cache contents. This flag is required.",
			EnvVar: "BAZEL_REMOTE_DIR",
		},
		cli.Int64Flag{
			Name:   "max_size",
			Value:  -1,
			Usage:  "The maximum size of the remote cache in GiB. This flag is required.",
			EnvVar: "BAZEL_REMOTE_MAX_SIZE",
		},
		cli.StringFlag{
			Name:   "host",
			Value:  "",
			Usage:  "Address to listen on. Listens on all network interfaces by default.",
			EnvVar: "BAZEL_REMOTE_HOST",
		},
		cli.IntFlag{
			Name:   "port",
			Value:  8080,
			Usage:  "The port the HTTP server listens on.",
			EnvVar: "BAZEL_REMOTE_PORT",
		},
		cli.StringFlag{
			Name:   "htpasswd_file",
			Value:  "",
			Usage:  "Path to a .htpasswd file. This flag is optional. Please read https://httpd.apache.org/docs/2.4/programs/htpasswd.html.",
			EnvVar: "BAZEL_REMOTE_HTPASSWD_FILE",
		},
		cli.BoolFlag{
			Name:   "tls_enabled",
			Usage:  "This flag has been deprecated. Specify tls_cert_file and tls_key_file instead.",
			EnvVar: "BAZEL_REMOTE_TLS_ENABLED",
		},
		cli.StringFlag{
			Name:   "tls_cert_file",
			Value:  "",
			Usage:  "Path to a pem encoded certificate file.",
			EnvVar: "BAZEL_REMOTE_TLS_CERT_FILE",
		},
		cli.StringFlag{
			Name:   "tls_key_file",
			Value:  "",
			Usage:  "Path to a pem encoded key file.",
			EnvVar: "BAZEL_REMOTE_TLS_KEY_FILE",
		},
	}

	app.Action = func(ctx *cli.Context) error {
		c, err := parseConfig(ctx)
		if err != nil {
			fmt.Fprintf(ctx.App.Writer, "%v\n\n", err)
			cli.ShowAppHelp(ctx)
			return nil
		}

		accessLogger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.LUTC)
		errorLogger := log.New(os.Stderr, "", log.Ldate|log.Ltime|log.LUTC)

		diskCache := cache.NewDiskCache(c.Dir, int64(c.MaxSize)*1024*1024*1024)

		var proxyCache cache.Cache
		if c.GoogleCloudStorage != nil {
			proxyCache, err = proxy.NewGCSProxyCache(c.GoogleCloudStorage.Bucket,
				c.GoogleCloudStorage.UseDefaultCredentials, c.GoogleCloudStorage.JSONCredentialsFile,
				diskCache, accessLogger, errorLogger)
			if err != nil {
				log.Fatal(err)
			}
		} else if c.HTTPBackend != nil {
			httpClient := &http.Client{}
			baseURL, err := url.Parse(c.HTTPBackend.BaseURL)
			if err != nil {
				log.Fatal(err)
			}
			proxyCache = proxy.NewHTTPProxyCache(baseURL, diskCache,
				httpClient, accessLogger, errorLogger)
		} else {
			proxyCache = diskCache
		}

		h := server.NewHTTPCache(proxyCache, accessLogger, errorLogger)

		http.HandleFunc("/status", h.StatusPageHandler)
		http.HandleFunc("/", maybeAuth(h.CacheHandler, c.HtpasswdFile, c.Host))

		if len(c.TLSCertFile) > 0 && len(c.TLSKeyFile) > 0 {
			return http.ListenAndServeTLS(c.Host+":"+strconv.Itoa(c.Port), c.TLSCertFile,
				c.TLSKeyFile, nil)
		}
		return http.ListenAndServe(c.Host+":"+strconv.Itoa(c.Port), nil)
	}

	serverErr := app.Run(os.Args)
	if serverErr != nil {
		log.Fatal("ListenAndServe: ", serverErr)
	}
}

func maybeAuth(fn http.HandlerFunc, htpasswdFile string, host string) http.HandlerFunc {
	if htpasswdFile != "" {
		secrets := auth.HtpasswdFileProvider(htpasswdFile)
		authenticator := auth.NewBasicAuthenticator(host, secrets)
		return auth.JustCheck(authenticator, fn)
	}
	return fn
}
