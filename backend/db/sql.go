package db

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/BurntSushi/toml"
	"github.com/go-sql-driver/mysql"
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

// configファイルからデータソース名を取得します
func GetDataSourceName() (string, string, error) {
	dir := getDirName()
	if dir == "" {
		e := errors.New("実行ファイル名の取得に失敗しました")
		return "", "", e
	}

	f := filepath.Join(dir, "connect.toml")
	var conf connectConfig

	if _, err := toml.DecodeFile(f, &conf); err != nil {
		return "", "", err
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
				return "", "", err
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
	}

	return conf.Type, dsn, nil
}

// SQLクエリ文を対象ファイルから取得します
func GetSQL(name string, req interface{}) string {
	dir := getDirName()
	if dir == "" {
		return ""
	}

	dbType, _, err := GetDataSourceName()
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	filename := filepath.Join(dir, dbType, fmt.Sprintf("%s.sql", name))

	t := template.Must(template.ParseFiles(filename))
	t.Execute(&buf, req)

	return buf.String()
}

// SQLファイルがあるディレクトリ名を取得します
func getDirName() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}

	return filepath.Base(exe) + ".sql"
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