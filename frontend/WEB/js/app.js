document.addEventListener('alpine:init', () => {
    Alpine.data('gocmApp', () => ({
        // API 設定
        apiUrl: localStorage.getItem('gocm_api_url') || 'http://127.0.0.1:8507/v1',
        
        // 認証・セッション情報 (sessionStorage 活用)
        caId: sessionStorage.getItem('gocm_ca_id') || '',
        password: sessionStorage.getItem('gocm_password') || '',
        isConnected: false,
        isLoading: false,

        // ナビゲーション状態
        activeTab: 'audit', // 'audit' | 'server' | 'client'

        // データホルダー
        caSummary: null,
        auditDays: 14,
        auditCerts: [],
        serverCerts: [],
        clientCerts: [],

        // 検索フィルタ
        searchQuery: '',

        // 新規発行フォーム状態
        newServer: {
            commonName: '',
            sanPrefix: 'DNS:',
            sanInput: '',
            sans: []
        },
        newClient: {
            commonName: ''
        },

        // モーダル表示状態
        showNewServerModal: false,
        showNewClientModal: false,

        // トースト通知システム
        toasts: [],

        init() {
            if (this.apiUrl.endsWith('/')) {
                this.apiUrl = this.apiUrl.slice(0, -1);
            }
            
            if (this.caId && this.password) {
                this.connect();
            }
        },

        saveApiUrl() {
            if (this.apiUrl.endsWith('/')) {
                this.apiUrl = this.apiUrl.slice(0, -1);
            }
            localStorage.setItem('gocm_api_url', this.apiUrl);
            this.notify('API接続URLを保存しました', 'success');
        },

        // 接続 ＆ データロード
        async connect() {
            if (!this.caId || !this.password) {
                this.notify('CA ID と パスワードを入力してください', 'warning');
                return;
            }

            this.isLoading = true;

            try {
                // CAサマリー情報の取得
                const res = await fetch(`${this.apiUrl}/ca/${encodeURIComponent(this.caId)}`, {
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });

                if (res.status === 403) {
                    throw new Error('パスワードの認証に失敗しました。');

                } else if (res.status === 404) {
                    throw new Error(`CA ID '${this.caId}' が見つかりませんでした。`);

                } else if (!res.ok) {
                    throw new Error(`接続エラー: HTTP ${res.status}`);
                }

                this.caSummary = await res.json();
                this.isConnected = true;

                // セッションストレージへ保存
                sessionStorage.setItem('gocm_ca_id', this.caId);
                sessionStorage.setItem('gocm_password', this.password);

                this.notify(`CA '${this.caId}' に正常に接続しました`, 'success');

                // 全データの初期読み込み
                await this.refreshAllData();

            } catch (err) {
                this.isConnected = false;
                this.caSummary = null;
                const msg = err.message === 'Failed to fetch' 
                    ? `GOCM サーバー (${this.apiUrl}) に接続できませんでした。バックエンドが起動しているか確認してください。` 
                    : err.message;
                this.notify(msg, 'error');

            } finally {
                this.isLoading = false;
            }
        },

        disconnect() {
            this.isConnected = false;
            this.caId = '';
            this.password = '';
            this.caSummary = null;
            this.auditCerts = [];
            this.serverCerts = [];
            this.clientCerts = [];
            this.searchQuery = '';
            this.newServer = { commonName: '', sanPrefix: 'DNS:', sanInput: '', sans: [] };
            this.newClient = { commonName: '' };
            this.showNewServerModal = false;
            this.showNewClientModal = false;

            sessionStorage.removeItem('gocm_ca_id');
            sessionStorage.removeItem('gocm_password');
            this.notify('切断し、セッション情報を完全に削除しました', 'info');
        },

        async refreshAllData() {
            if (!this.isConnected) return;
            await Promise.all([
                this.fetchAuditData(),
                this.fetchServerCerts(),
                this.fetchClientCerts(),
                this.fetchCASummary()
            ]);
        },

        async fetchCASummary() {
            try {
                const res = await fetch(`${this.apiUrl}/ca/${encodeURIComponent(this.caId)}`, {
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });
                if (res.ok) {
                    this.caSummary = await res.json();
                }
            } catch (e) {
                console.error('CAサマリー取得失敗:', e);
            }
        },

        // --- 1. 監査データ取得 ---
        async fetchAuditData() {
            try {
                const res = await fetch(`${this.apiUrl}/ca/${encodeURIComponent(this.caId)}/audit?days=${this.auditDays}`, {
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });
                if (res.ok) {
                    const data = await res.json();
                    this.auditCerts = data.certs || [];
                }
            } catch (err) {
                this.notify('監査データの取得に失敗しました', 'error');
            }
        },

        // --- 2. サーバー証明書一覧取得 ---
        async fetchServerCerts() {
            try {
                const res = await fetch(`${this.apiUrl}/certs/server/${encodeURIComponent(this.caId)}`, {
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });
                if (res.ok) {
                    const data = await res.json();
                    this.serverCerts = data.certs || [];
                }
            } catch (err) {
                this.notify('サーバー証明書一覧の取得に失敗しました', 'error');
            }
        },

        // --- 3. クライアント証明書一覧取得 ---
        async fetchClientCerts() {
            try {
                const res = await fetch(`${this.apiUrl}/certs/client/${encodeURIComponent(this.caId)}`, {
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });
                if (res.ok) {
                    const data = await res.json();
                    this.clientCerts = data.certs || [];
                }
            } catch (err) {
                this.notify('クライアント証明書一覧の取得に失敗しました', 'error');
            }
        },

        // --- 4. SAN (Subject Alt Name) タグ操作 ---
        addSan() {
            const val = this.newServer.sanInput.trim();
            if (!val) return;
            const fullSan = val.includes(':') ? val : `${this.newServer.sanPrefix}${val}`;
            if (!this.newServer.sans.includes(fullSan)) {
                this.newServer.sans.push(fullSan);
            }
            this.newServer.sanInput = '';
        },

        removeSan(index) {
            this.newServer.sans.splice(index, 1);
        },

        // --- 5. サーバー証明書 新規発行 (POST) ---
        async createServerCert() {
            if (!this.newServer.commonName.trim()) {
                this.notify('Common Name を入力してください', 'warning');
                return;
            }

            // 入力欄に未追加の文字列があれば自動追加
            if (this.newServer.sanInput.trim()) {
                this.addSan();
            }

            // SANが空の場合はデフォルトで DNS:<commonName> を追加
            let finalSans = [...this.newServer.sans];
            if (finalSans.length === 0) {
                finalSans = [`DNS:${this.newServer.commonName.trim()}`];
            }

            this.isLoading = true;
            try {
                const res = await fetch(`${this.apiUrl}/certs/server/${encodeURIComponent(this.caId)}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'GOCM-CA-PASSWORD': this.password
                    },
                    body: JSON.stringify({
                        common_name: this.newServer.commonName.trim(),
                        subject_alt_name: finalSans
                    })
                });

                if (res.status === 201) {
                    const data = await res.json();
                    this.notify(`サーバー証明書 '${data.common_name}' (Serial: ${data.serial}) を発行しました`, 'success');
                    this.showNewServerModal = false;
                    this.newServer = { commonName: '', sanPrefix: 'DNS:', sanInput: '', sans: [] };
                    await this.refreshAllData();
                } else {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.message || `発行失敗 HTTP ${res.status}`);
                }

            } catch (err) {
                this.notify(`サーバー証明書発行エラー: ${err.message}`, 'error');

            } finally {
                this.isLoading = false;
            }
        },

        // --- 6. クライアント証明書 新規発行 (POST) ---
        async createClientCert() {
            if (!this.newClient.commonName.trim()) {
                this.notify('Common Name を入力してください', 'warning');
                return;
            }

            this.isLoading = true;
            try {
                const res = await fetch(`${this.apiUrl}/certs/client/${encodeURIComponent(this.caId)}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'GOCM-CA-PASSWORD': this.password
                    },
                    body: JSON.stringify({
                        common_name: this.newClient.commonName.trim()
                    })
                });

                if (res.status === 201) {
                    const data = await res.json();
                    this.notify(`クライアント証明書 '${data.common_name}' (Serial: ${data.serial}) を発行しました`, 'success');
                    this.showNewClientModal = false;
                    this.newClient = { commonName: '' };
                    await this.refreshAllData();
                } else {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.message || `発行失敗 HTTP ${res.status}`);
                }

            } catch (err) {
                this.notify(`クライアント証明書発行エラー: ${err.message}`, 'error');

            } finally {
                this.isLoading = false;
            }
        },

        // --- 7. 証明書更新 (PUT) ---
        async renewCert(type, serial, commonName) {
            if (!confirm(`'${commonName}' (Serial: ${serial}) の証明書を更新しますか？`)) return;

            this.isLoading = true;
            try {
                const url = `${this.apiUrl}/certs/${type}/${encodeURIComponent(this.caId)}/${serial}`;
                const res = await fetch(url, {
                    method: 'PUT',
                    headers: { 'GOCM-CA-PASSWORD': this.password }
                });

                if (res.status === 201) {
                    const data = await res.json();
                    this.notify(`証明書 '${commonName}' を更新しました (新Serial: ${data.serial})`, 'success');
                    await this.refreshAllData();
                } else {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.message || `更新失敗 HTTP ${res.status}`);
                }

            } catch (err) {
                this.notify(`更新エラー: ${err.message}`, 'error');

            } finally {
                this.isLoading = false;
            }
        },

        // --- 8. ダウンロードヘルパー ---
        async downloadFile(url, filename, requiresAuth = false) {
            try {
                const headers = {};
                if (requiresAuth) {
                    headers['GOCM-CA-PASSWORD'] = this.password;
                }

                const res = await fetch(url, { headers });
                if (!res.ok) {
                    throw new Error(`取得失敗: HTTP ${res.status}`);
                }

                const text = await res.text();
                const blob = new Blob([text], { type: 'application/x-pem-file' });
                const blobUrl = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = blobUrl;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(blobUrl);

                this.notify(`'${filename}' をダウンロードしました`, 'info');

            } catch (err) {
                this.notify(`ダウンロード失敗: ${err.message}`, 'error');
            }
        },

        downloadCACert() {
            const url = `${this.apiUrl}/certs/ca/${encodeURIComponent(this.caId)}`;
            this.downloadFile(url, `${this.caId}_root_ca.crt`, false);
        },

        downloadServerCert(serial, commonName) {
            const url = `${this.apiUrl}/certs/server/${encodeURIComponent(this.caId)}/${serial}`;
            this.downloadFile(url, `${commonName}.crt`, false);
        },

        downloadServerKey(serial, commonName) {
            const url = `${this.apiUrl}/certs/server/${encodeURIComponent(this.caId)}/${serial}/secretkey?format=pem`;
            this.downloadFile(url, `${commonName}.key`, true);
        },

        downloadClientCert(serial, commonName) {
            const url = `${this.apiUrl}/certs/client/${encodeURIComponent(this.caId)}/${serial}`;
            this.downloadFile(url, `${commonName}.crt`, false);
        },

        downloadClientKey(serial, commonName) {
            const url = `${this.apiUrl}/certs/client/${encodeURIComponent(this.caId)}/${serial}/secretkey?format=pem`;
            this.downloadFile(url, `${commonName}.key`, true);
        },

        // --- 計算プロパティ / フィルタリング ---
        get rootCACert() {
            if (!this.caSummary || !Array.isArray(this.caSummary.valid_certs)) return null;
            return this.caSummary.valid_certs.find(c => c.cert_type === 'CA') || null;
        },

        get caExpirationDate() {
            return this.rootCACert?.expiration_date || '不明';
        },

        get filteredServerCerts() {
            if (!this.searchQuery.trim()) return this.serverCerts;
            const q = this.searchQuery.toLowerCase();
            return this.serverCerts.filter(c =>
                c.common_name.toLowerCase().includes(q) || String(c.serial).includes(q)
            );
        },

        get filteredClientCerts() {
            if (!this.searchQuery.trim()) return this.clientCerts;
            const q = this.searchQuery.toLowerCase();
            return this.clientCerts.filter(c =>
                c.common_name.toLowerCase().includes(q) || String(c.serial).includes(q)
            );
        },

        // 残り日数の計算ヘルパー
        getDaysRemaining(expirationDateStr) {
            if (!expirationDateStr) return 0;
            const exp = new Date(expirationDateStr);
            const now = new Date();
            const diffTime = exp.getTime() - now.getTime();
            return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        },

        // トースト表示関数
        notify(message, type = 'info') {
            const id = Date.now();
            this.toasts.push({ id, message, type });
            setTimeout(() => {
                this.toasts = this.toasts.filter(t => t.id !== id);
            }, 4000);
        }
    }));
});
