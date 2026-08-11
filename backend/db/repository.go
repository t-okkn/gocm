package db

import (
	"errors"

	"gocm-api/models"

	"github.com/go-gorp/gorp"
)

type Repository struct {
	*gorp.DbMap
}

// DBとの接続情報を作成します
func NewRepository(dm *gorp.DbMap) *Repository {
	return &Repository{dm}
}

// CA認証局の情報を取得します
func (r *Repository) GetCAInfo(id string) (models.TranCAInfo, error) {
	var result models.TranCAInfo
	query := GetSQL("get-cainfo", "")
	val := map[string]interface{}{"id": id}

	if err := r.SelectOne(&result, query, val); err != nil {
		return models.TranCAInfo{}, err
	}

	return result, nil
}

// 過去に発行された全てのCA証明書の枚数を取得します
func (r *Repository) CountCACert(id string) (int64, error) {
	query := GetSQL("count-ca-cert", "")
	val := map[string]interface{}{"id": id}

	return r.SelectInt(query, val)
}

// 有効なCA証明書を取得します
func (r *Repository) GetCACerts(id string) ([]models.TranCertificate, error) {
	var result []models.TranCertificate
	query := GetSQL("get-ca-cert", "")
	val := map[string]interface{}{"id": id}

	if _, err := r.Select(&result, query, val); err != nil {
		return []models.TranCertificate{}, err
	}

	return result, nil
}

// 有効なサーバ証明書を取得します
func (r *Repository) GetServerCerts(
	id string, req models.DBRequest) ([]models.TranCertificate, error) {

	var result []models.TranCertificate
	query := GetSQL("get-server-cert", req)
	val := map[string]interface{}{
		"id": id,
		"serial": req.Serial,
		"common_name": req.CommonName,
	}

	if _, err := r.Select(&result, query, val); err != nil {
		return []models.TranCertificate{}, err
	}

	return result, nil
}

// 有効なクライアント証明書を取得します
func (r *Repository) GetClientCerts(
	id string, req models.DBRequest) ([]models.TranCertificate, error) {

	var result []models.TranCertificate
	query := GetSQL("get-client-cert", req)
	val := map[string]interface{}{
		"id": id,
		"serial": req.Serial,
		"common_name": req.CommonName,
	}

	if _, err := r.Select(&result, query, val); err != nil {
		return []models.TranCertificate{}, err
	}

	return result, nil
}

// CA認証局の証明書を全て取得します
func (r *Repository) GetCASummary(id string) ([]models.SlimCertData, error) {
	var result []models.SlimCertData
	query := GetSQL("get-ca-summary", "")
	val := map[string]interface{}{"id": id}

	if _, err := r.Select(&result, query, val); err != nil {
		return []models.SlimCertData{}, err
	}

	return result, nil
}

// 認証局内のシリアル番号の最大値を取得します
func (r *Repository) GetMaxSerialNumber(id string) (int64, error) {
	query := GetSQL("get-max-serial", "")
	val := map[string]interface{}{"id": id}

	return r.SelectInt(query, val)
}

// 証明書の監査用データを取得します
func (r *Repository) AuditCertData(id string) ([]models.SlimCertData, error) {
	var result []models.SlimCertData
	query := GetSQL("audit-cert-data", "")
	val := map[string]interface{}{"id": id}

	if _, err := r.Select(&result, query, val); err != nil {
		return []models.SlimCertData{}, err
	}

	return result, nil
}

// CA認証局情報をDBへ追加します
func (r *Repository) InsertCAInfo(cainfo models.TranCAInfo) error {
	tx, err := r.Begin()

	if err != nil {
		return err
	}

	if err := tx.Insert(&cainfo); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

// 証明書情報をDBへ追加します
func (r *Repository) InsertCert(tcert models.TranCertificate) error {
	tx, err := r.Begin()

	if err != nil {
		return err
	}

	if err := tx.Insert(&tcert); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

// DBの証明書情報を更新します
func (r *Repository) UpdateCert(old, new models.TranCertificate) error {
	tx, err := r.Begin()

	if err != nil {
		return err
	}

	if _, err := tx.Update(&old); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Insert(&new); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

// CA認証局を削除する一連の操作をDB上で行います
func (r *Repository) DestroyCA(id string, tca models.TranCAInfo) error {
	var result []models.TranCertificate
	query := GetSQL("destroy-ca", "")
	val := map[string]interface{}{"id": id}

	tx, err := r.Begin()

	if err != nil {
		return err
	}

	if _, err := tx.Select(&result, query, val); err != nil {
		tx.Rollback()
		return err
	}

	if result == nil || len(result) == 0 {
		if err := tx.Commit(); err != nil {
			tx.Rollback()
			return err
		}

		return nil
	}

	// 1. 複数DeleteのためのinterfaceなSliceを準備する
	// （複数Insert、Updateでも同じ）
	delete_items := make([]interface{}, len(result))

	for i, v := range result {
		// 2. Deleteはポインタでないといけないが、直接ポインタで渡すと
		// 全て同じアドレス値を取り大変なことになるので、一度値を
		// 別の変数に詰め替える
		item := v

		// 3. interfaceなSliceにポインタを突っ込む
		delete_items[i] = &item
	}

	count, err := tx.Delete(delete_items...)

	if err != nil {
		tx.Rollback()
		return err
	}

	if _, err := tx.Delete(&tca); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return err
	}

	if count < int64(len(delete_items)) {
		return errors.New("削除した件数が異なっています")
	}

	return nil
}
