package models

// pkix.NameのSubject用構造体
type Subject struct {
	CommonName   string `json:"common_name" binding:"required"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	Organization string `json:"organization"`
}

// CA証明書発行用リクエスト
type NewCACertRequest struct {
	Subject             Subject `json:"subject" binding:"required"`
	PrivateKeyAlgorithm string  `json:"private_key_algorithm" binding:"required"`
	Bits                int     `json:"bits"`
}

// サーバ証明書発行用リクエスト
type NewServerCertRequest struct {
	CommonName     string   `json:"common_name" binding:"required"`
	SubjectAltName []string `json:"subject_alt_name" binding:"required"`
}

// クライアント証明書発行用リクエスト
type NewClientCertRequest struct {
	CommonName string `json:"common_name" binding:"required"`
}

// CA認証局作成時のレスポンス
type NewCAResponse struct {
	CAID     string `json:"ca_id"`
	Password string `json:"password"`
}

// 新規証明書発行時のレスポンス
type NewCertResponse struct {
	CAID       string `json:"ca_id"`
	Serial     uint32 `json:"serial"`
	CommonName string `json:"common_name"`
}

// CA認証局配下の証明書情報についてのレスポンス
type CAInfoResponse struct {
	CAID         string         `json:"ca_id"`
	ValidCerts   []CertSummary  `json:"valid_certs"`
	InvalidCerts []SlimCertData `json:"invalid_certs"`
}

// 証明書情報に関するレスポンス
type CertsResponse struct {
	CAID       string        `json:"ca_id"`
	Count      int           `json:"count"`
	CommonName string        `json:"common_name"`
	Certs      []CertSummary `json:"certs"`
}

// 証明書有効期限監査時のレスポンス
type AuditResponse struct {
	CAID         string        `json:"ca_id"`
	Days         int           `json:"days"`
	ExpectedDate string        `json:"expected_date"`
	Certs        []CertSummary `json:"certs"`
}

// 証明書情報のまとめ用構造体
type CertSummary struct {
	Serial         uint32 `json:"serial"`
	CommonName     string `json:"common_name"`
	CertType       string `json:"cert_type"`
	Created        string `json:"created"`
	ExpirationDate string `json:"expiration_date"`
}

// DBのクエリ用リクエスト
type DBRequest struct {
	Serial     uint32 `json:"serial"`
	CommonName string `json:"common_name"`
}
