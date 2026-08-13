#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import pathlib
import subprocess
import sys
import urllib.parse
from typing import List, Dict, Tuple

import requests

CERT_PATH_BASE = '/etc/ssl/private/'
DEFAULT_URL_BASE = 'http://127.0.0.1:8507/v1/'
LOG_FILE_PATH = '/var/log/gocm-cli.log'
CONFIG_FILE_NAME = 'secret.json'

# ロギング設定
logger = logging.getLogger('gocm-cli')

def setup_logging(verbose: bool = False):
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

    # コンソール出力ハンドラ
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ログファイル出力ハンドラ（書き込み可能な場合のみ）
    try:
        file_handler = logging.FileHandler(LOG_FILE_PATH, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    except Exception:
        # ログファイルへのアクセス権がない場合はコンソールのみ
        pass

def check_root_privileges() -> bool:
    if os.name == 'posix' and os.geteuid() != 0:
        warn = '注意: root権限で実行されていません。'
        warn += f'{CERT_PATH_BASE} 配下へのアクセスやパーミッション変更に失敗する可能性があります。'

        logger.warning(warn)
        return False

    return True

def load_secret_config(cert_dir: str) -> Tuple[str, str, str, str]:
    secret_path = os.path.join(cert_dir, CONFIG_FILE_NAME)

    if not os.path.isfile(secret_path):
        logger.error(f'{secret_path}: ファイルが存在しません')
        return '', '', DEFAULT_URL_BASE, ''

    try:
        with open(secret_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        ca_id = data.get('ca_id')
        password = data.get('password')
        api_url = data.get('api_url') or os.getenv('GOCM_API_URL') or DEFAULT_URL_BASE
        post_hook = data.get('post_hook')

        if not api_url.endswith('/'):
            api_url += '/'

        return ca_id, password, api_url, post_hook

    except Exception as e:
        logger.error(f'{secret_path} の読み込みエラー: {e}')
        return '', '', DEFAULT_URL_BASE, ''

def get_audit_data(url_base: str, ca_id: str, days: int) -> List[Dict]:
    result: List[Dict] = []
    url = urllib.parse.urljoin(url_base, f'ca/{ca_id}/audit?days={days}')

    try:
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            logger.error(f'調査データ取得失敗: HTTP {r.status_code} - {r.text}')
            return result

        j = r.json()
        certs = j.get('certs', [])

        for cert in certs:
            if cert.get('cert_type') == 'SERVER':
                result.append(cert)
            
    except requests.exceptions.RequestException as e:
        logger.error(f'APIリクエストエラー ({url}): {e}')

    return result

def get_common_names(cert_dir: str) -> List[str]:
    result: List[str] = []
    # 命名規則: {common_name}.key (例: xxx.example.com.key)
    key_list = pathlib.Path(cert_dir).glob('*.key')

    for k in key_list:
        cn = k.stem  # remove '.key' extension

        if cn:
            result.append(cn)

    return result

def run_post_hook(command: str, updated_domains: List[str]):
    logger.info(f'ポストフックコマンドを実行します: {command}')
    env = os.environ.copy()
    env['GOCM_UPDATED_DOMAINS'] = ','.join(updated_domains)

    try:
        res = subprocess.run(command, shell=True, capture_output=True, text=True, env=env)

        if res.returncode == 0:
            logger.info('ポストフックコマンドが成功しました')

            if res.stdout.strip():
                logger.info(f'ポストフック出力:\n{res.stdout.strip()}')

        else:
            logger.error(f'ポストフックコマンド失敗 (exit: {res.returncode}): {res.stderr.strip()}')

    except Exception as e:
        logger.error(f'ポストフック実行例外: {e}')

def update_cert(url_base: str, ca_id: str, password: str, cert: Dict, cert_dir: str) -> bool:
    serial = cert.get('serial')
    common_name = cert.get('common_name', '')

    upd_url = urllib.parse.urljoin(url_base, f'certs/server/{ca_id}/{serial}')
    headers = {'GOCM-CA-PASSWORD': password}

    try:
        r = requests.put(upd_url, headers=headers, timeout=15)
        if r.status_code != 201:
            logger.error(f'{common_name}: 証明書更新API失敗 HTTP {r.status_code} - {r.text}')
            return False

        new_serial = r.json().get('serial')
        cert_url = urllib.parse.urljoin(url_base, f'certs/server/{ca_id}/{new_serial}')
        r = requests.get(cert_url, timeout=15)

        if r.status_code != 200:
            logger.error(f'{common_name}: 新規証明書取得失敗 HTTP {r.status_code}')
            return False

        cert_path = os.path.join(cert_dir, f'{common_name}.crt')

        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(r.text)

        key_url = urllib.parse.urljoin(f'{cert_url}/', 'secretkey?format=pem')
        r = requests.get(key_url, headers=headers, timeout=15)

        if r.status_code != 200:
            logger.error(f'{common_name}: 新規秘密鍵取得失敗 HTTP {r.status_code}')
            return False

        key_path = os.path.join(cert_dir, f'{common_name}.key')

        with open(key_path, 'w', encoding='utf-8') as f:
            f.write(r.text)

        try:
            os.chmod(cert_path, 0o644)
            os.chmod(key_path, 0o600)

        except OSError as e:
            logger.warning(f'パーミッション変更警告 ({cert_path} / {key_path}): {e}')

        return True

    except requests.exceptions.RequestException as e:
        logger.error(f'{common_name}: 通信例外失敗: {e}')
        return False

def main():
    setup_logging()
    check_root_privileges()

    days = 20

    if len(sys.argv) == 2:
        try:
            days = int(sys.argv[1])
            if not (1 <= days <= 60):
                days = 20

        except ValueError:
            days = 20

    ca_id, password, url_base, post_hook = load_secret_config(CERT_PATH_BASE)
    secret_path = os.path.join(CERT_PATH_BASE, CONFIG_FILE_NAME)

    if not ca_id or not password:
        msg = '秘密情報 (ca_id / password) の取得に失敗しました。'
        msg += f'{secret_path} を確認してください。'

        logger.error(msg)
        sys.exit(126)

    logger.info(f'証明書の調査を開始します (対象CA: {ca_id}, 残り日数閾値: {days}日, 接続先: {url_base})')

    audit_data = get_audit_data(url_base, ca_id, days)
    common_names = get_common_names(CERT_PATH_BASE)

    if not audit_data:
        logger.info('期限切れ間近の更新対象証明書はありませんでした。')
        sys.exit(0)

    if not common_names:
        logger.warning(f'保管場所 ({CERT_PATH_BASE}) にローカル証明書の鍵 (*.key) が存在しません。')
        sys.exit(0)

    updated_count = 0
    error_count = 0
    updated_domains = []

    for cert in audit_data:
        cn = cert.get('common_name')
        if cn in common_names:
            logger.info(f'{cn}: 更新処理を実行します')

            res = update_cert(url_base, ca_id, password, cert, CERT_PATH_BASE)

            if res:
                logger.info(f'{cn}: 正常に更新しました')
                updated_count += 1
                updated_domains.append(cn)

            else:
                logger.error(f'{cn}: 更新に失敗しました')
                error_count += 1

    if updated_count > 0 and post_hook:
        run_post_hook(post_hook, updated_domains)

    if error_count > 0:
        logger.error(f'更新処理で {error_count} 件のエラーが発生しました。')
        sys.exit(1)

    else:
        logger.info('すべての対象証明書の確認・更新処理が完了しました。')
        sys.exit(0)

if __name__ == '__main__':
    main()
