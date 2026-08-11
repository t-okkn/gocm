package models

import (
	"github.com/go-gorp/gorp"
)

type MstrCertType struct {
	CertType string `db:"cert_type" json:"cert_type"`
}

type TranCAInfo struct {
	Id       string `db:"id, primarykey" json:"id"`
	Password string `db:"password" json:"password"`
	Created  string `db:"created" json:"created"`
}

type TranCertificate struct {
	CAID           string `db:"ca_id, primarykey" json:"ca_id"`
	Serial         uint32 `db:"serial, primarykey" json:"serial"`
	CommonName     string `db:"common_name" json:"common_name"`
	PrivateKey     string `db:"private_key" json:"private_key"`
	CertType       string `db:"cert_type" json:"cert_type"`
	CertData       string `db:"cert_data" json:"cert_data"`
	Created        string `db:"created" json:"created"`
	ExpirationDate string `db:"expiration_date" json:"expiration_date"`
	IsRevoked      int    `db:"is_revoked" json:"is_revoked"`
	Revoked        string `db:"revoked" json:"revoked"`
}

// 証明書データ・秘密鍵データがない軽量版データのレスポンス
type SlimCertData struct {
	CAID           string `db:"ca_id, primarykey" json:"ca_id"`
	Serial         uint32 `db:"serial, primarykey" json:"serial"`
	CommonName     string `db:"common_name" json:"common_name"`
	CertType       string `db:"cert_type" json:"cert_type"`
	Created        string `db:"created" json:"created"`
	ExpirationDate string `db:"expiration_date" json:"expiration_date"`
	IsRevoked      int    `db:"is_revoked" json:"is_revoked"`
	Revoked        string `db:"revoked" json:"revoked"`
}

// MapStructsToTables 構造体と物理テーブルの紐付け
func MapStructsToTables(dbmap *gorp.DbMap) {
	dbmap.AddTableWithName(MstrCertType{}, "M_CERT_TYPE").SetKeys(false, "CertType")
	dbmap.AddTableWithName(TranCAInfo{}, "T_CAINFO").SetKeys(false, "Id")
	dbmap.AddTableWithName(TranCertificate{}, "T_CERTIFICATE").SetKeys(false, "CAID", "Serial")
}
