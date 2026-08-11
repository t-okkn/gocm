package db

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/go-sql-driver/mysql"
	"github.com/BurntSushi/toml"
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
	IsDisable bool   `toml:"disable"`
	IsCaOnly  bool   `toml:"caonly"`
	CA        string `toml:"ca"`
	Cert      string `toml:"cert"`
	Key       string `toml:"key"`
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

		if !conf.DB.TLS.IsDisable {
			if err := registerMysqlTLSConfig(conf.DB.TLS); err != nil {
				return "", "", err
			}

			dsn += "?tls=custom"
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

	var buf bytes.Buffer
	filename := fmt.Sprintf("%s/%s.sql", dir, name)

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
	rootCertPool := x509.NewCertPool()

	pem, err := ioutil.ReadFile(tlsi.CA)
	if err != nil {
		return err
	}

	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		e := errors.New("CA証明書の追加に失敗しました")
		return e
	}

	if tlsi.IsCaOnly {
		mysql.RegisterTLSConfig("custom", &tls.Config{
			ClientCAs: rootCertPool,
		})

	} else {
		certs, err := tls.LoadX509KeyPair(tlsi.Cert, tlsi.Key)
		if err != nil {
			return err
		}

		clientCert := make([]tls.Certificate, 0, 1)
		clientCert = append(clientCert, certs)

		mysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
		})
	}

	return nil
}