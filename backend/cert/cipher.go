package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"unsafe"
)

// パスワードを生成します
//
// ※実態は共通暗号鍵です
func GeneratePassword() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b64str := base64.URLEncoding.EncodeToString(b)
	return fmt.Sprintf("pk.%s", b64str), nil
}

// パスワードをハッシュ化します
func GetHashedPassword(password string) (string, error) {
	if (len([]rune(password)) >= 73) {
		e := "73文字以上のパスワードは指定できません"
		return "", errors.New(e)
	}

	pp := (*[]byte)(unsafe.Pointer(&password))
	hash, err := bcrypt.GenerateFromPassword(*pp, bcrypt.DefaultCost)

	if err != nil {
		return "", err

	} else {
		return base64.StdEncoding.EncodeToString(hash), nil
	}
}

// パスワードとハッシュ化されたパスワードを照合します
func VerifyPassword(hashedPass, password string) error {
	pp := (*[]byte)(unsafe.Pointer(&password))
	hash, err := base64.StdEncoding.DecodeString(hashedPass)

	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword(hash, *pp)
}

// 秘密鍵を暗号化します
func encrypt(password, pemstr string) (string, error) {
	key, err := passwordToKey(password)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Unique nonce is required(NonceSize 12byte)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	cipherdata := gcm.Seal(nil, nonce, []byte(pemstr), nil)
	cipherdata = append(nonce, cipherdata...)

	return base64.StdEncoding.EncodeToString(cipherdata), nil
}

// 秘密鍵を復号します
func decrypt(password, base64Text string) (string, error) {
	key, err := passwordToKey(password)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(base64Text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	size := gcm.NonceSize()
	pemdata, err := gcm.Open(nil, data[:size], data[size:], nil)
	if err != nil {
		return "", err
	}

	return string(pemdata), nil
}

// 文字列としての秘密鍵をバイナリデータに変換します
func passwordToKey(password string) ([]byte, error) {
	if !strings.HasPrefix(password, "pk.") {
		e := errors.New("不正なパスワードです")
		return []byte{}, e
	}

	splitted := strings.Split(password, ".")
	key, err := base64.URLEncoding.DecodeString(splitted[1])

	if err != nil {
		return []byte{}, err
	}

	return key, nil
}
