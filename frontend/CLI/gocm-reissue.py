#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
from typing import List, Dict, Tuple

import requests

CERT_PATH_BASE = '/etc/ssl/private/'
DEFAULT_URL_BASE = 'http://127.0.0.1:8507/v1/'
LOG_FILE_PATH = '/var/log/gocm-cli.log'
CONFIG_FILE_NAME = 'secret.json'

logger = logging.getLogger('gocm-reissue')

def setup_logging(verbose: bool = False):
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        file_handler = logging.FileHandler(LOG_FILE_PATH, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
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

def extract_sans_from_cert(cert_path: str) -> List[str]:
    """既存の.crtファイルから 'DNS:...' や 'IP:...' などの形式でSANを抽出します"""
    if not os.path.isfile(cert_path):
        return []

    try:
        res = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-ext', 'subjectAltName'],
            capture_output=True, text=True, check=True
        )
        sans = []
        for line in res.stdout.splitlines():
            for m in re.finditer(r'DNS:([^\s,]+)', line):
                sans.append(f"DNS:{m.group(1)}")

            for m in re.finditer(r'IP Address:([^\s,]+)', line):
                sans.append(f"IP:{m.group(1)}")

            for m in re.finditer(r'URI:([^\s,]+)', line):
                sans.append(f"URI:{m.group(1)}")

            for m in re.finditer(r'email:([^\s,]+)', line):
                sans.append(f"email:{m.group(1)}")

        return sans

    except Exception as e:
        logger.warning(f'{cert_path} からのSAN抽出失敗: {e}')
        return []

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

def reissue_server_cert(url_base: str, ca_id: str, password: str, common_name: str, cert_dir: str) -> bool:
    cert_path = os.path.join(cert_dir, f'{common_name}.crt')
    key_path = os.path.join(cert_dir, f'{common_name}.key')

    # SANの抽出（なければデフォルトで DNS:{common_name} を指定）
    sans = extract_sans_from_cert(cert_path)
    if not sans:
        logger.info(f'{common_name}: 既存証明書からSANを取得できなかったため、DNS:{common_name} を使用します')
        sans = [f"DNS:{common_name}"]

    else:
        logger.info(f'{common_name}: 既存証明書からSANを抽出しました: {sans}')

    post_url = urllib.parse.urljoin(url_base, f'certs/server/{ca_id}')
    headers = {
        'GOCM-CA-PASSWORD': password,
        'Content-Type': 'application/json'
    }
    payload = {
        'common_name': common_name,
        'subject_alt_name': sans
    }

    try:
        r = requests.post(post_url, json=payload, headers=headers, timeout=15)
        if r.status_code != 201:
            logger.error(f'{common_name}: 証明書新規再発行API失敗 HTTP {r.status_code} - {r.text}')
            return False

        new_serial = r.json().get('serial')
        logger.info(f'{common_name}: 新規証明書の発行に成功しました (新Serial: {new_serial})')

        # 新証明書の取得
        cert_url = urllib.parse.urljoin(url_base, f'certs/server/{ca_id}/{new_serial}')
        r = requests.get(cert_url, timeout=15)

        if r.status_code != 200:
            logger.error(f'{common_name}: 新規証明書取得失敗 HTTP {r.status_code}')
            return False

        with open(cert_path, 'w', encoding='utf-8') as f:
            f.write(r.text)

        # 新秘密鍵の取得
        key_url = urllib.parse.urljoin(f'{cert_url}/', 'secretkey?format=pem')
        r = requests.get(key_url, headers=headers, timeout=15)
        if r.status_code != 200:
            logger.error(f'{common_name}: 新規秘密鍵取得失敗 HTTP {r.status_code}')
            return False

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

def get_existing_common_names(cert_dir: str) -> List[str]:
    result: List[str] = []

    for k in pathlib.Path(cert_dir).glob('*.key'):
        cn = k.stem
        if cn:
            result.append(cn)

    return result

def main():
    setup_logging()
    check_root_privileges()

    ca_id, password, url_base, post_hook = load_secret_config(CERT_PATH_BASE)
    secret_path = os.path.join(CERT_PATH_BASE, CONFIG_FILE_NAME)

    if not ca_id or not password:
        logger.error(f'秘密情報 (ca_id / password) の取得に失敗しました。{secret_path} を確認してください。')
        sys.exit(126)

    targets = []

    if len(sys.argv) >= 2:
        targets = sys.argv[1:]

    else:
        existing = get_existing_common_names(CERT_PATH_BASE)

        if not existing:
            logger.error(f'対象の Common Name が指定されておらず、{CERT_PATH_BASE} に *.key も見つかりませんでした。')
            logger.info('使用法: gocm-reissue.py <common_name_1> [common_name_2 ...]')
            sys.exit(1)

        targets = existing

    logger.info(f'証明書の手動再発行を開始します (対象CA: {ca_id}, 対象: {", ".join(targets)})')

    success_count = 0
    error_count = 0
    reissued_domains = []

    for cn in targets:
        logger.info(f'{cn}: 再発行処理を実行します')

        if reissue_server_cert(url_base, ca_id, password, cn, CERT_PATH_BASE):
            logger.info(f'{cn}: 再発行・更新が完了しました')
            success_count += 1
            reissued_domains.append(cn)

        else:
            logger.error(f'{cn}: 再発行処理に失敗しました')
            error_count += 1

    if success_count > 0 and post_hook:
        run_post_hook(post_hook, reissued_domains)

    if error_count > 0:
        logger.error(f'再発行処理で {error_count} 件のエラーが発生しました。')
        sys.exit(1)
        
    else:
        logger.info('すべての対象証明書の再発行処理が完了しました。')
        sys.exit(0)

if __name__ == '__main__':
    main()
