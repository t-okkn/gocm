package main

type ErrorMessage struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

var (
	// E001: DBと接続できません
	errCannotConnectDB = ErrorMessage{
		Code   : "E001",
		Message: "DBと接続できません",
	}

	// E002: データの操作に失敗しました
	errFailedOperateData = ErrorMessage{
		Code   : "E002",
		Message: "データの操作に失敗しました",
	}

	// E003: データの取得に失敗しました
	errFailedGetData = ErrorMessage{
		Code   : "E003",
		Message: "データの取得に失敗しました",
	}

	// E101: リクエストされたデータが不正です
	errInvalidRequestedData = ErrorMessage{
		Code   : "E101",
		Message: "リクエストされたデータが不正です",
	}

	// E102: 不正なアルゴリズムが指定されています
	errInvalidAlgorithm = ErrorMessage{
		Code   : "E102",
		Message: "不正なアルゴリズムが指定されています",
	}

	// E103: 指定されたアルゴリズムに対して非対応のビット数です
	errIncompatibleBits = ErrorMessage{
		Code   : "E103",
		Message: "指定されたアルゴリズムに対して非対応のビット数です",
	}

	// E104: リクエストされたURLが正しくありません
	errInvalidURL = ErrorMessage{
		Code   : "E104",
		Message: "リクエストされたURLが正しくありません",
	}

	// E105: Subject AltNameとして有効なデータが存在しませんでした
	errInvalidSANs = ErrorMessage{
		Code   : "E105",
		Message: "Subject AltNameとして有効なデータが存在しませんでした",
	}

	// E106: Serial値が有効な数値ではありません
	errInvalidSerial = ErrorMessage{
		Code   : "E106",
		Message: "Serial値が有効な数値ではありません",
	}

	// E201: 既に有効なCA証明書が存在しています
	errExistsValidCACert = ErrorMessage{
		Code   : "E201",
		Message: "既に有効なCA証明書が存在しています",
	}

	// E202: 有効なCA証明書が存在しません
	errNotFoundValidCACert = ErrorMessage{
		Code   : "E202",
		Message: "有効なCA証明書が存在しません",
	}

	// E203: 証明書ストアが不正な状態になっています
	errInvalidCertStore = ErrorMessage{
		Code   : "E203",
		Message: "証明書ストアが不正な状態になっています",
	}

	// E204: 有効なサーバ証明書が存在しません
	errNotFoundValidServerCert = ErrorMessage{
		Code   : "E204",
		Message: "有効なサーバ証明書が存在しません",
	}

	// E205: 有効なクライアント証明書が存在しません
	errNotFoundValidClientCert = ErrorMessage{
		Code   : "E205",
		Message: "有効なクライアント証明書が存在しません",
	}

	// E301: 証明書へのアクセス権限がありません
	errFailedAccess = ErrorMessage{
		Code   : "E301",
		Message: "証明書へのアクセス権限がありません",
	}
)