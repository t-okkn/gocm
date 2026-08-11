package main

import (
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-gorp/gorp"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"gocm-api/cert"
	"gocm-api/db"
	"gocm-api/models"
)

const (
	CA_PASSWORD   string = "GOCM-CA-PASSWORD"
	DEFAULT_AUDIT int    = 30
)

var (
	repo *db.Repository

	// a-z, A-Z, 0-9, *-._, SP
	allowRune = []rune{
		32, 42, 45, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66,
		67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
		83, 84, 85, 86, 87, 88, 89, 90, 95, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
		115, 116, 117, 118, 119, 120, 121, 122,
	}
)

/*
// memo:
// CA証明書新規：何も証明書がない or 有効期限切れの証明書しかない状態で発行
// CA証明書更新：有効な証明書が1枚だけ存在する状態で破棄＆新規発行
// その他証明書新規：何もせず新規発行
// その他証明書更新：特定の有効な証明書を破棄＆新規発行
*/

// 待ち受けるサーバのルーターを定義します
//
// httpHandlerを受け取る関数にそのまま渡せます
func SetupRouter() *gin.Engine {
	router := gin.Default()
	v1 := router.Group("v1")

	v1.POST("/ca", newCA)
	v1.GET("/ca/:id", getCAInfo)
	v1.DELETE("/ca/:id", destroyCA)

	v1.GET("/ca/:id/audit", auditAllCerts)

	certs := v1.Group("certs")

	certs.POST("/ca/:id", newCACert)
	certs.GET("/ca/:id", getCACert)
	certs.GET("/ca/:id/secretkey", getCACert)
	certs.PUT("/ca/:id", updateCACert)

	certs.POST("/server/:id", newServerCert)
	certs.GET("/server/:id", listServerCerts)
	certs.GET("/server/:id/:serial", getServerCert)
	certs.GET("/server/:id/:serial/secretkey", getServerCert)
	certs.PUT("/server/:id/:serial", updateServerCert)

	certs.POST("/client/:id", newClientCert)
	certs.GET("/client/:id", listClientCerts)
	certs.GET("/client/:id/:serial", getClientCert)
	certs.GET("/client/:id/:serial/secretkey", getClientCert)
	certs.PUT("/client/:id/:serial", updateClientCert)

	repo = initDB()

	return router
}

// 新規CA認証局を作成します
func newCA(c *gin.Context) {
	obj, err := uuid.NewRandom()

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	id := obj.String()
	password, err := cert.GeneratePassword()

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	hash, err := cert.GetHashedPassword(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	cainfo := models.TranCAInfo{
		Id:       id,
		Password: hash,
		Created:  getNowString(),
	}

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	if err := repo.InsertCAInfo(cainfo); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCAResponse{
		CAID:     id,
		Password: password,
	})
}

// CA認証局内の証明書発行状況・破棄状況を表示します
func getCAInfo(c *gin.Context) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	caid := cainfo.Id
	certs, err := repo.GetCASummary(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	response := models.CAInfoResponse{CAID: caid}
	response.ValidCerts = make([]models.CertSummary, 0, len(certs))
	response.InvalidCerts = make([]models.SlimCertData, 0, len(certs))

	if len(certs) == 0 {
		c.JSON(http.StatusOK, response)
		return
	}

	for _, cert := range certs {
		expire := getParsedTime(cert.ExpirationDate)

		if cert.IsRevoked == 1 || expire.Before(time.Now()) {
			response.InvalidCerts = append(response.InvalidCerts, cert)

		} else {
			summary := models.CertSummary{
				Serial:         cert.Serial,
				CommonName:     cert.CommonName,
				CertType:       cert.CertType,
				Created:        cert.Created,
				ExpirationDate: cert.ExpirationDate,
			}
			response.ValidCerts = append(response.ValidCerts, summary)
		}
	}

	c.JSON(http.StatusOK, response)
}

// CA認証局とそれらに紐づく証明書を全て削除します
func destroyCA(c *gin.Context) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	if _, ok := checkPassword(c, cainfo.Password); !ok {
		return
	}

	if err := repo.DestroyCA(cainfo.Id, cainfo); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.Status(http.StatusNoContent)
}

// CA認証局内の証明書について有効期限を監査します
//
// デフォルトは30日後に有効期限を迎える証明書を表示します
func auditAllCerts(c *gin.Context) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	caid := cainfo.Id
	certs, err := repo.AuditCertData(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	days_str := fmt.Sprintf("%d", DEFAULT_AUDIT)
	days_qry := c.DefaultQuery("days", days_str)
	days, err := strconv.Atoi(days_qry)

	// 不正な文字列、1未満365より大きい数は強制的に30日
	if err != nil || (days < 1 || days > 365) {
		days = DEFAULT_AUDIT
	}

	expected := time.Now().AddDate(0, 0, days)
	response := models.AuditResponse{
		CAID:         caid,
		Days:         days,
		ExpectedDate: expected.Format(cert.DT_FORMAT),
	}
	response.Certs = make([]models.CertSummary, 0, len(certs))

	if len(certs) == 0 {
		c.JSON(http.StatusOK, response)
		return
	}

	for _, cert := range certs {
		expire := getParsedTime(cert.ExpirationDate)

		// 現在からdays日後の時間が期限前であれば無視
		if expected.Before(expire) {
			continue
		}

		summary := models.CertSummary{
			Serial:         cert.Serial,
			CommonName:     cert.CommonName,
			CertType:       cert.CertType,
			Created:        cert.Created,
			ExpirationDate: cert.ExpirationDate,
		}

		response.Certs = append(response.Certs, summary)
	}

	c.JSON(http.StatusOK, response)
}

// CA証明書の情報をCER形式で取得します
func getCACert(c *gin.Context) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	if strings.Contains(c.FullPath(), "secretkey") {
		password, ok := checkPassword(c, cainfo.Password)
		if !ok {
			return
		}

		cert_data, err := cert.ToCertData(password, cadata[0])

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		pem, err := cert_data.PrivateKey.ToPem()

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		content_type := "application/x-pem-file; charset=utf-8"
		c.Data(http.StatusOK, content_type, []byte(pem))

	} else {
		content_type := "application/pkix-cert; charset=utf-8"
		byte_data := []byte(cadata[0].CertData)
		c.Data(http.StatusOK, content_type, byte_data)
	}

	// こちらでも問題はない
	// https://github.com/gin-gonic/gin/issues/468
	//c.Header("Content-Type", "application/pkix-cert")
	//c.String(http.StatusOK, cadata[0].CertData)
}

// 発行されたサーバ証明書の一覧を表示します
func listServerCerts(c *gin.Context) {
	listCertData(c, cert.SERVER)
}

// 発行されたクライアント証明書の一覧を表示します
func listClientCerts(c *gin.Context) {
	listCertData(c, cert.CLIENT)
}

// 発行されたサーバ証明書を取得します
//
// CER形式の証明書データを出力します
func getServerCert(c *gin.Context) {
	getCertificate(c, cert.SERVER)
}

// 発行されたクライアント証明書を取得します
//
// PFX形式の証明書データを出力します
func getClientCert(c *gin.Context) {
	getCertificate(c, cert.CLIENT)
}

// 新規CA証明書を発行します
func newCACert(c *gin.Context) {
	newCertificate(c, cert.CA)
}

// 新規サーバ証明書を発行します
func newServerCert(c *gin.Context) {
	newCertificate(c, cert.SERVER)
}

// 新規クライアント証明書を発行します
func newClientCert(c *gin.Context) {
	newCertificate(c, cert.CLIENT)
}

// 既存の有効なCA証明書を更新します
func updateCACert(c *gin.Context) {
	updateCertificate(c, cert.CA)
}

// 既存の有効なサーバ証明書を更新します
func updateServerCert(c *gin.Context) {
	updateCertificate(c, cert.SERVER)
}

// 既存の有効なクライアント証明書を更新します
func updateClientCert(c *gin.Context) {
	updateCertificate(c, cert.CLIENT)
}

// 認証局の情報を取得します
func getCAInfoData(c *gin.Context) (models.TranCAInfo, bool) {
	id_prm := c.Param("id")
	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return models.TranCAInfo{}, false
	}

	return cainfo, true
}

// リクエストされたパスワードが正しいか確認し、
// 正しい場合はパスワードを取得します
func checkPassword(c *gin.Context, hashedPass string) (string, bool) {
	password := c.GetHeader(CA_PASSWORD)

	if err := cert.VerifyPassword(hashedPass, password); err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return "", false
	}

	return password, true
}

// サーバ・クライアント証明書の一覧を取得します
func listCertData(c *gin.Context, certType cert.CertType) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	common_name := sanitize(c.DefaultQuery("cn", ""))
	db_req := models.DBRequest{
		Serial:     0,
		CommonName: common_name,
	}

	caid := cainfo.Id
	var data []models.TranCertificate
	var err error

	if certType == cert.SERVER {
		data, err = repo.GetServerCerts(caid, db_req)

	} else if certType == cert.CLIENT {
		data, err = repo.GetClientCerts(caid, db_req)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	res := models.CertsResponse{
		CAID:       caid,
		Count:      len(data),
		CommonName: common_name,
	}
	res.Certs = make([]models.CertSummary, len(data))

	for i, item := range data {
		res.Certs[i] = models.CertSummary{
			Serial:         item.Serial,
			CommonName:     item.CommonName,
			CertType:       item.CertType,
			Created:        item.Created,
			ExpirationDate: item.ExpirationDate,
		}
	}

	c.JSON(http.StatusOK, res)
}

// サーバ・クライアント証明書を取得します
func getCertificate(c *gin.Context, certType cert.CertType) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	serial_prm := c.Param("serial")
	serial, err := strconv.ParseUint(serial_prm, 10, 0)

	if err != nil || serial > uint64(^uint32(0)) {
		c.JSON(http.StatusBadRequest, errInvalidSerial)
		c.Abort()
		return
	}

	// CommonNameが空文字でもSQL問い合わせ時によしなに処理してくれる
	db_req := models.DBRequest{
		Serial:     uint32(serial),
		CommonName: "",
	}

	caid := cainfo.Id
	var tran_data []models.TranCertificate
	var not_found ErrorMessage

	if certType == cert.SERVER {
		tran_data, err = repo.GetServerCerts(caid, db_req)
		not_found = errNotFoundValidServerCert

	} else if certType == cert.CLIENT {
		tran_data, err = repo.GetClientCerts(caid, db_req)
		not_found = errNotFoundValidClientCert
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(tran_data) == 0 {
		c.JSON(http.StatusNotFound, not_found)
		c.Abort()
		return

	} else if len(tran_data) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	c.Header("GOCM-REQUEST-SERIAL", fmt.Sprintf("%d", serial))

	if strings.Contains(c.FullPath(), "secretkey") {
		password, ok := checkPassword(c, cainfo.Password)
		if !ok {
			return
		}

		cert_data, err := cert.ToCertData(password, tran_data[0])

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		format := sanitize(c.DefaultQuery("format", "pem"))

		switch format {
		case "pem":
			pem, err := cert_data.PrivateKey.ToPem()

			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorMessage{
					Code:    "E501",
					Message: err.Error(),
				})
				c.Abort()
				return
			}

			content_type := "application/x-pem-file; charset=utf-8"
			c.Data(http.StatusOK, content_type, []byte(pem))

		case "pkcs12", "p12", "pfx":
			default_pin := string([]rune(getNowString())[:10])
			pin := sanitize(c.DefaultQuery("pin", default_pin))

			if pin == "" {
				pin = default_pin
			}

			pkcs12, err := cert_data.ToPkcs12(pin)

			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorMessage{
					Code:    "E501",
					Message: err.Error(),
				})
				c.Abort()
				return
			}

			c.Header("GOCM-REQUEST-PIN", pin)
			content_type := "application/x-pkcs12"
			c.Data(http.StatusOK, content_type, pkcs12)
		}

	} else {
		content_type := "application/pkix-cert; charset=utf-8"
		byte_data := []byte(tran_data[0].CertData)
		c.Data(http.StatusOK, content_type, byte_data)
	}
}

// 各種証明書を新規発行します
func newCertificate(c *gin.Context, certType cert.CertType) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	// -----
	// 有効なCA証明書の取得を試みます
	// -----
	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	// -----
	// CA証明書の状態に関しての確認を行います
	// -----
	var ca_count int64 = 0

	switch certType {
	case cert.CA:
		ca_count, err = repo.CountCACert(caid)

		if err != nil {
			c.JSON(http.StatusInternalServerError, errFailedGetData)
			c.Abort()
			return
		}

		// CA証明書が1枚も発行されていない場合はCA証明書に関するチェックは不要
		if ca_count == 0 {
			break
		}

		if len(cadata) == 1 {
			c.JSON(http.StatusConflict, errExistsValidCACert)
			c.Abort()
			return

		} else if len(cadata) > 1 {
			c.JSON(http.StatusInternalServerError, errInvalidCertStore)
			c.Abort()
			return
		}

	case cert.SERVER, cert.CLIENT:
		if len(cadata) == 0 {
			c.JSON(http.StatusNotFound, errNotFoundValidCACert)
			c.Abort()
			return

		} else if len(cadata) > 1 {
			c.JSON(http.StatusInternalServerError, errInvalidCertStore)
			c.Abort()
			return
		}
	}

	password, ok := checkPassword(c, cainfo.Password)
	if !ok {
		return
	}

	// -----
	// CA証明書とシリアル番号の取得を行います
	// -----
	var serial uint32 = 1
	var ca *cert.CertData

	// シリアル番号を更新するかどうかを決める変数
	is_updatable := true

	switch certType {
	case cert.CA:
		if ca_count == 0 {
			is_updatable = false
		}

	case cert.SERVER, cert.CLIENT:
		ca, err = cert.ToCertData(password, cadata[0])

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}
	}

	if is_updatable {
		max, err := repo.GetMaxSerialNumber(caid)

		if err != nil {
			c.JSON(http.StatusInternalServerError, errFailedGetData)
			c.Abort()
			return
		}

		serial = uint32(max) + 1
	}

	// -----
	// 各種証明書の発行を行います
	// -----
	var newcert *cert.CertData

	switch certType {
	case cert.CA:
		var req models.NewCACertRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		if req.Subject.CommonName == "" {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		certreq, ok := getCACertRequest(c, req)

		if !ok {
			return
		}

		certreq.CAID = caid
		certreq.Serial = serial
		newcert, err = cert.CreateCACert(certreq)

	case cert.SERVER:
		var req models.NewServerCertRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		if req.CommonName == "" {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		certreq, ok := getServerCertRequest(req)

		if !ok {
			c.JSON(http.StatusBadRequest, errInvalidSANs)
			c.Abort()
			return
		}

		certreq.Serial = serial
		newcert, err = cert.CreateServerCert(certreq, ca)

	case cert.CLIENT:
		var req models.NewClientCertRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		if req.CommonName == "" {
			c.JSON(http.StatusBadRequest, errInvalidRequestedData)
			c.Abort()
			return
		}

		newcert, err = cert.CreateClientCert(serial, req.CommonName, ca)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	// -----
	// DBへ証明書データを格納します
	// -----
	db_newcert, err := newcert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	if err := repo.InsertCert(db_newcert); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	// -----
	// クライアントへ発行した証明書の情報を渡します
	// -----
	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     serial,
		CommonName: db_newcert.CommonName,
	})
}

// 有効な各種証明書を更新します
func updateCertificate(c *gin.Context, certType cert.CertType) {
	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, ok := getCAInfoData(c)
	if !ok {
		return
	}

	// -----
	// 有効なCA証明書の取得を試みます
	// -----
	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	// -----
	// CA証明書の状態に関しての確認を行います
	// -----
	switch certType {
	case cert.CA:
		ca_count, err := repo.CountCACert(caid)

		if err != nil {
			c.JSON(http.StatusInternalServerError, errFailedGetData)
			c.Abort()
			return
		}

		if ca_count == 0 || (ca_count != 1 && len(cadata) == 0) {
			c.JSON(http.StatusNotFound, errNotFoundValidCACert)
			c.Abort()
			return
		}

	case cert.SERVER, cert.CLIENT:
		if len(cadata) == 0 {
			c.JSON(http.StatusNotFound, errNotFoundValidCACert)
			c.Abort()
			return
		}
	}

	if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	// -----
	// DBから更新すべき証明書のデータを取得します
	// -----
	var old_data models.TranCertificate

	switch certType {
	case cert.CA:
		old_data = cadata[0]

	case cert.SERVER, cert.CLIENT:
		serial_prm := c.Param("serial")
		old_serial, err := strconv.ParseUint(serial_prm, 10, 0)

		if err != nil || old_serial > uint64(^uint32(0)) {
			c.JSON(http.StatusBadRequest, errInvalidSerial)
			c.Abort()
			return
		}

		db_req := models.DBRequest{
			Serial:     uint32(old_serial),
			CommonName: "",
		}

		var data []models.TranCertificate
		var err_msg ErrorMessage

		if certType == cert.SERVER {
			data, err = repo.GetServerCerts(caid, db_req)
			err_msg = errNotFoundValidServerCert

		} else if certType == cert.CLIENT {
			data, err = repo.GetClientCerts(caid, db_req)
			err_msg = errNotFoundValidClientCert
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, errFailedGetData)
			c.Abort()
			return
		}

		if len(data) == 0 {
			c.JSON(http.StatusNotFound, err_msg)
			c.Abort()
			return

		} else if len(data) > 1 {
			c.JSON(http.StatusInternalServerError, errInvalidCertStore)
			c.Abort()
			return
		}

		old_data = data[0]
	}

	// パスワード確認
	password, ok := checkPassword(c, cainfo.Password)
	if !ok {
		return
	}

	// CA証明書の秘密鍵等の読み込み
	cacert, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	// シリアル番号の取得
	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	new_serial := uint32(max) + 1

	// -----
	// 更新後の証明書を発行します
	// -----
	var new_cert *cert.CertData

	switch certType {
	case cert.CA:
		new_cert, err = cacert.UpdateCert(new_serial, nil)

	case cert.SERVER, cert.CLIENT:
		var old_cert *cert.CertData
		old_cert, err = cert.ToCertData(password, old_data)

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		new_cert, err = old_cert.UpdateCert(new_serial, cacert)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	// -----
	// DBへ証明書データを格納します
	// -----
	new_data, err := new_cert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	// 更新前のデータは破棄扱い
	old_data.IsRevoked = 1
	old_data.Revoked = getNowString()

	if err := repo.UpdateCert(old_data, new_data); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	// -----
	// クライアントへ発行した証明書の情報を渡します
	// -----
	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     new_serial,
		CommonName: new_data.CommonName,
	})
}

// CA証明書発行のための情報を取得します
func getCACertRequest(c *gin.Context, data models.NewCACertRequest) (
	*cert.CreateCACertRequest, bool) {

	var cakey cert.PrivateKey
	var err error

	switch strings.ToUpper(data.PrivateKeyAlgorithm) {
	case "RSA":
		if data.Bits != 2048 && data.Bits != 4096 {
			c.JSON(http.StatusBadRequest, errIncompatibleBits)
			c.Abort()
			return nil, false
		}

		cakey, err = cert.GenerateRSAKey(data.Bits)

	case "ECDSA":
		if data.Bits != 256 && data.Bits != 384 && data.Bits != 521 {
			c.JSON(http.StatusBadRequest, errIncompatibleBits)
			c.Abort()
			return nil, false
		}

		cakey, err = cert.GenerateECDSAKey(data.Bits)

	case "ED25519":
		cakey, err = cert.GenerateED25519Key()

	default:
		c.JSON(http.StatusBadRequest, errInvalidAlgorithm)
		c.Abort()
		return nil, false
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return nil, false
	}

	name := pkix.Name{
		CommonName: data.Subject.CommonName,
	}

	if data.Subject.Country != "" {
		name.Country = []string{data.Subject.Country}
	}

	if data.Subject.State != "" {
		name.Province = []string{data.Subject.State}
	}

	if data.Subject.Locality != "" {
		name.Locality = []string{data.Subject.Locality}
	}

	if data.Subject.Organization != "" {
		name.Organization = []string{data.Subject.Organization}
	}

	req := &cert.CreateCACertRequest{
		PrivateKey: cakey,
		Subject:    name,
	}

	return req, true
}

// サーバ証明書発行のための情報を取得します
func getServerCertRequest(
	data models.NewServerCertRequest) (*cert.CreateServerCertRequest, bool) {

	req := cert.CreateServerCertRequest{
		CommonName: data.CommonName,
	}

	req.DNSNames = make([]string, 0, len(data.SubjectAltName))
	req.IPAddresses = make([]net.IP, 0, len(data.SubjectAltName))
	req.URIs = make([]*url.URL, 0, len(data.SubjectAltName))
	req.EmailAddresses = make([]string, 0, len(data.SubjectAltName))

	for _, v := range data.SubjectAltName {
		switch {
		case strings.HasPrefix(v, "DNS:"):
			content := strings.Replace(v, "DNS:", "", 1)
			req.DNSNames = append(req.DNSNames, content)

		case strings.HasPrefix(v, "IP:"):
			content := strings.Replace(v, "IP:", "", 1)
			ipdata := net.ParseIP(content)

			if ipdata == nil {
				break
			}

			req.IPAddresses = append(req.IPAddresses, ipdata)

		case strings.HasPrefix(v, "URI:"):
			content := strings.Replace(v, "URI:", "", 1)
			urldata, err := url.Parse(content)

			if err != nil {
				break
			}

			req.URIs = append(req.URIs, urldata)

		case strings.HasPrefix(v, "email:"):
			content := strings.Replace(v, "email:", "", 1)
			req.EmailAddresses = append(req.EmailAddresses, content)
		}
	}

	if len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 &&
		len(req.URIs) == 0 && len(req.EmailAddresses) == 0 {

		return nil, false
	}

	return &req, true
}

// DBとの接続についての初期処理を行います
func initDB() *db.Repository {
	driver, dsn, err := db.GetDataSourceName()
	if err != nil {
		fmt.Println("E001 :", err)
		return nil
	}

	var dbmap *gorp.DbMap

	switch driver {
	case "mysql":
		op, _ := sql.Open(driver, dsn)
		dial := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "utf8mb4"}

		dbmap = &gorp.DbMap{Db: op, Dialect: dial, ExpandSliceArgs: true}
		models.MapStructsToTables(dbmap)
	}

	return db.NewRepository(dbmap)
}

// 許可されている文字以外を除外します
func sanitize(input string) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, char := range input {
		for _, r := range allowRune {
			if char == r {
				sb.WriteRune(char)
				break
			}
		}
	}

	return sb.String()
}

// SQLに登録されている文字列型の時間をtime.Time型へ変換します
func getParsedTime(strTime string) time.Time {
	loc, _ := time.LoadLocation("Asia/Tokyo")

	t, err := time.ParseInLocation(cert.DT_FORMAT, strTime, loc)
	if err != nil {
		return time.Date(1970, 1, 1, 9, 0, 0, 0, loc)
	}

	return t
}

// 現在時刻を示す文字列を取得します
func getNowString() string {
	return time.Now().Format(cert.DT_FORMAT)
}
