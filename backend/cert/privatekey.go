package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type PrivateKeyAlgorithm string

type PrivateKey struct {
	Algorithm PrivateKeyAlgorithm
	Key       crypto.Signer
}

const (
	UNKNOWN_ALGORITHM PrivateKeyAlgorithm = "UNKNOWN"
	RSA               PrivateKeyAlgorithm = "RSA"
	ECDSA             PrivateKeyAlgorithm = "ECDSA"
	ED25519           PrivateKeyAlgorithm = "ED25519"
)

// RSA PrivateKeyを生成します
//
// ※2048bit, 4096bitにのみ対応しています
func GenerateRSAKey(bits int) (PrivateKey, error) {
	if bits != 2048 && bits != 4096 {
		e := fmt.Sprintf("指定したビット数（%dbit）には対応していません", bits)
		return PrivateKey{}, errors.New(e)
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)

	if err != nil {
		return PrivateKey{}, err
	}

	k := PrivateKey{
		Algorithm: RSA,
		Key:       priv,
	}

	return k, nil
}


// ECDSA PrivateKeyを生成します
//
// ※P-256, P-384, P-521にのみ対応しています
func GenerateECDSAKey(bits int) (PrivateKey, error) {
	var curve elliptic.Curve

	switch bits {
	case 256:
		curve = elliptic.P256()

	case 384:
		curve = elliptic.P384()

	case 521:
		curve = elliptic.P521()

	default:
		e := fmt.Sprintf("指定したビット数（%dbit）には対応していません", bits)
		return PrivateKey{}, errors.New(e)
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return PrivateKey{}, err
	}

	k := PrivateKey{
		Algorithm: ECDSA,
		Key:       priv,
	}

	return k, nil
}

//ED25519 PrivateKeyを生成します
func GenerateED25519Key() (PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return PrivateKey{}, err
	}

	k := PrivateKey{
		Algorithm: ED25519,
		Key:       priv,
	}

	return k, nil
}

// PrivateKey構造体からPEM形式のデータに変換します
func (priv PrivateKey) ToPem() (string, error) {
	var (
		priv_dsr []byte
		err      error
		priv_blk *pem.Block
	)

	switch key := any(priv.Key).(type) {
	case *rsa.PrivateKey:
		priv_dsr = x509.MarshalPKCS1PrivateKey(key)

		priv_blk = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priv_dsr,
		}

	case *ecdsa.PrivateKey:
		priv_dsr, err = x509.MarshalECPrivateKey(key)

		if err != nil {
			return "", err
		}

		priv_blk = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: priv_dsr,
		}

	case ed25519.PrivateKey:
		priv_dsr, err = x509.MarshalPKCS8PrivateKey(key)

		if err != nil {
			return "", err
		}

		priv_blk = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: priv_dsr,
		}

	default:
		e := errors.New("入力された秘密鍵は非対応のアルゴリズムです")
		return "", e
	}

	b := pem.EncodeToMemory(priv_blk)

	if b != nil {
		return string(b), nil

	} else {
		e := errors.New("PEM形式のデータ変換に失敗しました")
		return "", e
	}
}

// PEM形式のデータをPrivateKey構造体に変換します
func toPrivateKey(key string) (PrivateKey, error) {
	if len(key) == 0 {
		return PrivateKey{}, errors.New("PEM形式の秘密鍵を入力してください")
	}

	block, _ := pem.Decode([]byte(key))

	if block == nil {
		return PrivateKey{}, errors.New("DER形式のデータ変換に失敗しました")
	}

	var priv interface{}
	var err error
	var algo PrivateKeyAlgorithm = UNKNOWN_ALGORITHM

	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		algo = RSA

	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(block.Bytes)
		algo = ECDSA

	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		algo = ED25519

	default:
		e := errors.New("入力されたPEM形式のデータは秘密鍵ではありません")
		return PrivateKey{}, e
	}

	if err != nil {
		return PrivateKey{}, err
	}

	if value, ok := priv.(crypto.Signer); ok {
		k := PrivateKey{
			Algorithm: algo,
			Key:       value,
		}

		return k, nil

	} else {
		e := errors.New("入力されたPEM形式のデータは無効な秘密鍵です")
		return PrivateKey{}, e
	}
}

// PrivateKeyの鍵サイズを取得します
func (priv PrivateKey) getKeySize() int {
	switch priv.Algorithm {
	case RSA:
		key, ok := priv.Key.(*rsa.PrivateKey)

		if ok {
			size := key.D.BitLen()

			switch {
			case size >= 2032 && size <= 2048:
				return 2048

			case size >= 4080 && size <= 4096:
				return 4096
			}
		}

	case ECDSA:
		key, ok := priv.Key.(*ecdsa.PrivateKey)

		if ok {
			size := key.D.BitLen()

			switch {
			case size >= 240 && size <= 256:
				return 256

			case size >= 368 && size <= 384:
				return 384

			case size >= 505 && size <= 521:
				return 521
			}
		}

	case ED25519:
		return 0
	}

	return -1
}
