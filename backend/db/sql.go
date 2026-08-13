package db

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/go-sql-driver/mysql"
)

const (
	envGocmConnectPath string = "GOCM_CONNECT_PATH"
	configFileName     string = "connect.toml"
)

//go:embed SQLFiles/*/*.sql
var sqlFiles embed.FS

// メモリ上に永続化（キャッシュ）するパッケージ変数
var (
	cachedDBType string
	cachedDSN    string
	loadErr      error
	configOnce   sync.Once
)

type connectConfig struct {
	Type string         `toml:"db_type"`
	DB   databaseConfig `toml:"database"`
}

type databaseConfig struct {
	User     string  `toml:"user"`
	Password string  `toml:"password"`
	Server   string  `toml:"server"`
	Port     int     `toml:"port"`
	DBName   string  `toml:"name"`
	TLS      tlsInfo `toml:"tls"`
}

type tlsInfo struct {
	SSLMode string `toml:"sslmode"`
	CA      string `toml:"ca"`
	Cert    string `toml:"cert"`
	Key     string `toml:"key"`
}

// findConnectConfigFile: 設定ファイル connect.toml の存在するパスを順番に探索します
func findConnectConfigFile() (string, error) {
	candidates := make([]string, 5)
	appName := ""
	exeDir := ""

	if exe, err := os.Executable(); err == nil {
		appName = filepath.Base(exe)
		exeDir = filepath.Dir(exe)
	}

	// 1. バイナリと同じ階層
	candidates = append(candidates, filepath.Join(exeDir, configFileName))

	// 2. 環境変数 GOCM_CONNECT_PATH
	if envPath := os.Getenv(envGocmConnectPath); envPath != "" {
		candidates = append(candidates, envPath)
	}

	// 3. /etc 配下
	etc := filepath.Join("/etc", appName, configFileName)
	candidates = append(candidates, etc)

	// 4. /usr/local/etc 配下
	localEtc := filepath.Join("/usr/local/etc", appName, configFileName)
	candidates = append(candidates, localEtc)

	for _, p := range candidates {
		if p == "" {
			continue
		}

		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	err := fmt.Errorf(
		"設定ファイル (%s) が見つかりませんでした (検索パス: %v)",
		configFileName, candidates)

	return "", err
}

// 初回アクセス時のみ connect.toml を読み込み、メモリに永続化
func initConfigOnce() {
	configFile, err := findConnectConfigFile()
	if err != nil {
		loadErr = err
		return
	}

	var conf connectConfig
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		loadErr = fmt.Errorf("設定ファイル (%s) の読み込みに失敗しました: %w", configFile, err)
		return
	}

	var dsn string

	switch conf.Type {
	case "mysql":
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			conf.DB.User,
			conf.DB.Password,
			conf.DB.Server,
			conf.DB.Port,
			conf.DB.DBName)

		if conf.DB.TLS.SSLMode != "" && conf.DB.TLS.SSLMode != "disable" {
			if err := registerMysqlTLSConfig(conf.DB.TLS); err != nil {
				loadErr = err
				return
			}

			dsn += "?tls=custom"
		}

	case "postgres":
		sslmode := conf.DB.TLS.SSLMode

		if sslmode == "" {
			sslmode = "disable"
		}

		dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			conf.DB.Server,
			conf.DB.Port,
			conf.DB.User,
			conf.DB.Password,
			conf.DB.DBName,
			sslmode)

		if sslmode != "disable" {
			if conf.DB.TLS.CA != "" {
				dsn += fmt.Sprintf(" sslrootcert=%s", conf.DB.TLS.CA)
			}
			if conf.DB.TLS.Cert != "" && conf.DB.TLS.Key != "" {
				dsn += fmt.Sprintf(" sslcert=%s sslkey=%s", conf.DB.TLS.Cert, conf.DB.TLS.Key)
			}
		}

	default:
		loadErr = fmt.Errorf("未対応のDBタイプです: %s", conf.Type)
		return
	}

	cachedDBType = conf.Type
	cachedDSN = dsn
}

// GetDBType: メモリ上の DB タイプ (mysql / postgres) のみを返します
func GetDBType() (string, error) {
	configOnce.Do(initConfigOnce)

	if loadErr != nil {
		return "", loadErr
	}

	return cachedDBType, nil
}

// GetDataSourceName: メモリ上の DB タイプと DSN を返します (DB接続確立用)
func GetDataSourceName() (string, error) {
	configOnce.Do(initConfigOnce)

	if loadErr != nil {
		return "", loadErr
	}

	return cachedDSN, nil
}

// GetSQL: DB タイプのみを参照し、埋め込み SQL テンプレートからクエリを生成します
func GetSQL(name string, req any) string {
	dbType, err := GetDBType()
	if err != nil {
		return ""
	}

	path := fmt.Sprintf("SQLFiles/%s/%s.sql", dbType, name)
	content, err := sqlFiles.ReadFile(path)
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	t := template.Must(template.New(name).Parse(string(content)))
	t.Execute(&buf, req)

	return buf.String()
}

// MySQLの接続情報にTLS情報を付与します
func registerMysqlTLSConfig(tlsi tlsInfo) error {
	tlsConfig := &tls.Config{}

	switch tlsi.SSLMode {
	case "require":
		tlsConfig.InsecureSkipVerify = true

	case "verify-ca", "verify-full":
		if tlsi.CA != "" {
			rootCertPool := x509.NewCertPool()
			pem, err := ioutil.ReadFile(tlsi.CA)

			if err != nil {
				return err
			}

			if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
				return errors.New("CA証明書の追加に失敗しました")
			}

			tlsConfig.RootCAs = rootCertPool
		}
		
		if tlsi.SSLMode == "verify-ca" {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	if tlsi.Cert != "" && tlsi.Key != "" {
		certs, err := tls.LoadX509KeyPair(tlsi.Cert, tlsi.Key)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{certs}
	}

	mysql.RegisterTLSConfig("custom", tlsConfig)
	return nil
}