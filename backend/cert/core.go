package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"gocm/models"
)

type CertType string

type CertData struct {
	CAID           string
	Serial         uint32
	CommonName     string
	PrivateKey     PrivateKey
	Type           CertType
	PemData        string
	Created        string
	ExpirationDate string
}

type CreateCACertRequest struct {
	CAID       string
	PrivateKey PrivateKey
	Subject    pkix.Name
	Serial     uint32
}

type CreateServerCertRequest struct {
	CommonName     string
	Serial         uint32
	DNSNames       []string
	IPAddresses    []net.IP
	URIs           []*url.URL
	EmailAddresses []string
}

const (
	DTFormat string = "2006-01-02T15:04:05"

	caExpire time.Duration = 3153600000 * time.Second // 100年
	svExpire time.Duration = 8640000 * time.Second    // 100日
	clExpire time.Duration = 3153600000 * time.Second // 100年

	UnknownCertType CertType = "UNKNOWN"
	CA              CertType = "CA"
	SERVER          CertType = "SERVER"
	CLIENT          CertType = "CLIENT"
)

// GenerateBase32ID: 15バイトの乱数から24文字のBase32文字列を生成します
func GenerateBase32ID() (string, error) {
	b := make([]byte, 15)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(encoder.EncodeToString(b)), nil
}

// CA証明書を発行します
func CreateCACert(req *CreateCACertRequest) (*CertData, error) {

	created := time.Now()
	expire := created.Add(caExpire)
	usage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(req.Serial)),
		Subject:               req.Subject,
		NotAfter:              expire,
		NotBefore:             created,
		KeyUsage:              usage,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	priv := req.PrivateKey.Key
	pemData, err := createCertificate(tpl, tpl, priv.Public(), priv)

	if err != nil {
		return nil, err
	}

	data := CertData{
		CAID:           req.CAID,
		Serial:         req.Serial,
		CommonName:     req.Subject.CommonName,
		PrivateKey:     req.PrivateKey,
		Type:           CA,
		PemData:        pemData,
		Created:        created.Format(DTFormat),
		ExpirationDate: expire.Format(DTFormat),
	}

	return &data, nil
}

// サーバ証明書を発行します
func CreateServerCert(
	req *CreateServerCertRequest, ca *CertData) (*CertData, error) {

	cacert, err := ca.toX509CertificateData()

	if err != nil {
		return nil, err
	}

	created := time.Now()
	expire := created.Add(svExpire)

	usage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement

	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
	}

	subject := cacert.Subject
	subject.CommonName = req.CommonName

	tpl := &x509.Certificate{
		SerialNumber:   big.NewInt(int64(req.Serial)),
		Subject:        subject,
		NotAfter:       expire,
		NotBefore:      created,
		KeyUsage:       usage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		URIs:           req.URIs,
		EmailAddresses: req.EmailAddresses,
	}

	priv, err := ca.newPrivateKey()

	if err != nil {
		return nil, err
	}

	pemData, err := createCertificate(
		tpl, cacert, priv.Key.Public(), ca.PrivateKey.Key)

	if err != nil {
		return nil, err
	}

	data := CertData{
		CAID:           ca.CAID,
		Serial:         req.Serial,
		CommonName:     req.CommonName,
		PrivateKey:     priv,
		Type:           SERVER,
		PemData:        pemData,
		Created:        created.Format(DTFormat),
		ExpirationDate: expire.Format(DTFormat),
	}

	return &data, nil
}

// クライアント証明書を発行します
func CreateClientCert(
	serial uint32, commonName string, ca *CertData) (*CertData, error) {

	cacert, err := ca.toX509CertificateData()

	if err != nil {
		return nil, err
	}

	created := time.Now()
	expire := created.Add(clExpire)

	usage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment

	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	}

	subject := cacert.Subject
	subject.CommonName = commonName

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serial)),
		Subject:      subject,
		NotAfter:     expire,
		NotBefore:    created,
		KeyUsage:     usage,
		ExtKeyUsage:  extKeyUsage,
	}

	priv, err := ca.newPrivateKey()

	if err != nil {
		return nil, err
	}

	pemData, err := createCertificate(
		tpl, cacert, priv.Key.Public(), ca.PrivateKey.Key)

	if err != nil {
		return nil, err
	}

	data := CertData{
		CAID:           ca.CAID,
		Serial:         serial,
		CommonName:     subject.CommonName,
		PrivateKey:     priv,
		Type:           CLIENT,
		PemData:        pemData,
		Created:        created.Format(DTFormat),
		ExpirationDate: expire.Format(DTFormat),
	}

	return &data, nil
}

// DB上の証明書情報をプログラム内部で扱う証明書情報に変換します
func ToCertData(
	password string, tcert models.TranCertificate) (*CertData, error) {

	pempk, err := decrypt(password, tcert.PrivateKey)

	if err != nil {
		return nil, err
	}

	priv, err := toPrivateKey(pempk)

	if err != nil {
		return nil, err
	}

	cert := &CertData{
		CAID:           tcert.CAID,
		Serial:         tcert.Serial,
		CommonName:     tcert.CommonName,
		PrivateKey:     priv,
		Type:           CertType(tcert.CertType),
		PemData:        tcert.CertData,
		Created:        tcert.Created,
		ExpirationDate: tcert.ExpirationDate,
	}

	return cert, nil
}

// 証明書を更新します
func (c *CertData) UpdateCert(serial uint32, ca *CertData) (*CertData, error) {
	oldCert, err := c.toX509CertificateData()

	if err != nil {
		return nil, err
	}

	created := time.Now()
	expire := created.Add(oldCert.NotAfter.Sub(oldCert.NotBefore))

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(serial)),
		Subject:               oldCert.Subject,
		NotAfter:              expire,
		NotBefore:             created,
		KeyUsage:              oldCert.KeyUsage,
		ExtKeyUsage:           oldCert.ExtKeyUsage,
		DNSNames:              oldCert.DNSNames,
		IPAddresses:           oldCert.IPAddresses,
		URIs:                  oldCert.URIs,
		EmailAddresses:        oldCert.EmailAddresses,
		IsCA:                  oldCert.IsCA,
		BasicConstraintsValid: oldCert.BasicConstraintsValid,
	}

	priv, err := c.newPrivateKey()

	if err != nil {
		return nil, err
	}

	var pemData string

	if c.Type == CA {
		pemData, err = createCertificate(tpl, tpl, priv.Key.Public(), priv.Key)

	} else {
		cacert, err := ca.toX509CertificateData()

		if err != nil {
			return nil, err
		}

		pemData, err = createCertificate(
			tpl, cacert, priv.Key.Public(), ca.PrivateKey.Key)
	}

	if err != nil {
		return nil, err
	}

	data := CertData{
		CAID:           c.CAID,
		Serial:         serial,
		CommonName:     tpl.Subject.CommonName,
		PrivateKey:     priv,
		Type:           c.Type,
		PemData:        pemData,
		Created:        created.Format(DTFormat),
		ExpirationDate: expire.Format(DTFormat),
	}

	return &data, nil
}

// クライアント証明書 or サーバ証明書と秘密鍵をPFX形式のデータにします
func (c *CertData) ToPkcs12(pin string) ([]byte, error) {
	if c.Type == CA {
		e := errors.New("CA証明書のデータには対応していません")
		return nil, e
	}

	cert, err := c.toX509CertificateData()

	if err != nil {
		return []byte{}, err
	}

	return pkcs12.Encode(rand.Reader, c.PrivateKey.Key, cert, nil, pin)
}

// プログラム内部で扱う証明書情報をDB上の証明書情報に変換します
func (c *CertData) TranCertificate(
	password string) (models.TranCertificate, error) {

	priv, err := c.PrivateKey.ToPem()

	if err != nil {
		return models.TranCertificate{}, err
	}

	encrypted, err := encrypt(password, priv)

	if err != nil {
		return models.TranCertificate{}, err
	}

	tc := models.TranCertificate{
		CAID:           c.CAID,
		Serial:         c.Serial,
		CommonName:     c.CommonName,
		PrivateKey:     encrypted,
		CertType:       string(c.Type),
		CertData:       c.PemData,
		Created:        c.Created,
		ExpirationDate: c.ExpirationDate,
		IsRevoked:      false,
		Revoked:        "",
	}

	return tc, nil
}

// x509.CreateCertificate関数をラッピングし、PEM形式の証明書データを出力します
func createCertificate(template *x509.Certificate, parent *x509.Certificate,
	pub crypto.PublicKey, priv crypto.Signer) (string, error) {

	cert, err := x509.CreateCertificate(
		rand.Reader, template, parent, pub, priv)

	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	data := pem.EncodeToMemory(block)

	if data != nil {
		return string(data), nil

	} else {
		e := errors.New("PEM形式のデータ変換に失敗しました")
		return "", e
	}
}

// 既存の証明書情報から新規秘密鍵を生成します
func (c *CertData) newPrivateKey() (PrivateKey, error) {
	var priv PrivateKey
	var err error

	switch c.PrivateKey.Algorithm {
	case RSA:
		size := c.PrivateKey.getKeySize()

		if size < 2048 {
			err := errors.New("秘密鍵のRSA鍵長が取得できませんでした")
			return PrivateKey{}, err
		}

		priv, err = GenerateRSAKey(size)

	case ECDSA:
		size := c.PrivateKey.getKeySize()

		if size < 256 {
			err := errors.New("秘密鍵のECDSA鍵長が取得できませんでした")
			return PrivateKey{}, err
		}

		priv, err = GenerateECDSAKey(size)

	case ED25519:
		priv, err = GenerateED25519Key()
	}

	if err != nil {
		return PrivateKey{}, err

	} else {
		return priv, nil
	}
}

// PEM形式の証明書データからx509.Certificate構造体へ変換します
func (c *CertData) toX509CertificateData() (*x509.Certificate, error) {
	if len(c.PemData) == 0 {
		return nil, errors.New("PEM形式の証明書データがありません")
	}

	block, _ := pem.Decode([]byte(c.PemData))

	if block == nil {
		return nil, errors.New("DER形式のデータ変換に失敗しました")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("入力されたデータは証明書データではありません")
	}

	return x509.ParseCertificate(block.Bytes)
}
