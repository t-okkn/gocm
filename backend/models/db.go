package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-gorp/gorp"
)

// BitBool: MySQL の BIT(1) と PostgreSQL の BOOLEAN の両方に対応する bool 型
type BitBool bool

type MstrCertType struct {
	CertType string `db:"cert_type" json:"cert_type"`
}

type TranCAInfo struct {
	Id       int64  `db:"id, primarykey, autoincrement" json:"-"`
	CAID     string `db:"ca_id" json:"id"`
	Password string `db:"password" json:"password"`
	Created  string `db:"created" json:"created"`
}

type TranCertificate struct {
	Id             int64   `db:"id, primarykey, autoincrement" json:"-"`
	CAID           string  `db:"ca_id" json:"ca_id"`
	Serial         uint32  `db:"serial" json:"serial"`
	CommonName     string  `db:"common_name" json:"common_name"`
	PrivateKey     string  `db:"private_key" json:"private_key"`
	CertType       string  `db:"cert_type" json:"cert_type"`
	CertData       string  `db:"cert_data" json:"cert_data"`
	Created        string  `db:"created" json:"created"`
	ExpirationDate string  `db:"expiration_date" json:"expiration_date"`
	IsRevoked      BitBool `db:"is_revoked" json:"is_revoked"`
	Revoked        string  `db:"revoked" json:"revoked"`
}

// 証明書データ・秘密鍵データがない軽量版データのレスポンス
type SlimCertData struct {
	Id             int64   `db:"id, primarykey, autoincrement" json:"-"`
	CAID           string  `db:"ca_id" json:"ca_id"`
	Serial         uint32  `db:"serial" json:"serial"`
	CommonName     string  `db:"common_name" json:"common_name"`
	CertType       string  `db:"cert_type" json:"cert_type"`
	Created        string  `db:"created" json:"created"`
	ExpirationDate string  `db:"expiration_date" json:"expiration_date"`
	IsRevoked      BitBool `db:"is_revoked" json:"is_revoked"`
	Revoked        string  `db:"revoked" json:"revoked"`
}

// MapStructsToTables 構造体と物理テーブルの紐付け
func MapStructsToTables(driver string, dbmap *gorp.DbMap) {
	certType := "M_CERT_TYPE"
	cainfo := "T_CAINFO"
	cert := "T_CERTIFICATE"

	if driver == "postgres" {
		certType = strings.ToLower(certType)
		cainfo = strings.ToLower(cainfo)
		cert = strings.ToLower(cert)
	}

	dbmap.AddTableWithName(MstrCertType{}, certType).SetKeys(false, "CertType")
	dbmap.AddTableWithName(TranCAInfo{}, cainfo).SetKeys(false, "Id")
	dbmap.AddTableWithName(TranCertificate{}, cert).SetKeys(false, "CAID", "Serial")
}

// Value: DBへの書き込み (CUD) 時に呼び出されます
func (b BitBool) Value() (driver.Value, error) {
	if b {
		return int64(1), nil
	}

	return int64(0), nil
}

// Scan: DBからの読み込み (SELECT) 時に呼び出されます
func (b *BitBool) Scan(src any) error {
	if src == nil {
		*b = false
		return nil
	}

	switch v := src.(type) {
	case []byte: // MySQL BIT(1)
		*b = BitBool(len(v) > 0 && v[0] != 0)

	case int64:
		*b = BitBool(v != 0)

	case bool: // PostgreSQL BOOLEAN
		*b = BitBool(v)

	default:
		return fmt.Errorf("読み込んだ %T 型を BitBool に変換できませんでした", src)
	}

	return nil
}

// MarshalJSON: APIレスポンス用 (true/false として出力)
func (b BitBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(b))
}

// UnmarshalJSON: APIリクエスト用
func (b *BitBool) UnmarshalJSON(data []byte) error {
	var v bool

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*b = BitBool(v)

	return nil
}
