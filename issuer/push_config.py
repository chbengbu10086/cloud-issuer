"""push_config.py — 本地一键推送配置：签名 + GitHub 原子提交 + CF KV 写入 + 回访验签。

通道约定（与客户端 config_center.cpp 对齐）：
  - Cloudflare 主通道：Worker GET /config?id=N，从 KV 读 config_N（原文）+ config_N_sig
    （base64 签名），原样返回 body + X-Config-Sign 头，绝不现签。
  - GitHub 备通道：main 分支 config/config_N.txt + config/config_N.sig（256 字节原始签名）。

凭证来源（优先级从高到低）：
  环境变量 → 工作区（配置推送工具/）一键推送配置.local.json（gitignore）→ 代码默认值（仅非密标识）。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .sign_config import (
    sign_config_bytes,
    _load_private_key_from_file,
    _load_private_key_from_string,
)

# 仓库根：<root>/reference/cloud_issuer/issuer/push_config.py → parents[3] = <root>
# 入口脚本（配置推送工具/一键推送配置.py）会显式传入这两个环境变量以解耦目录布局。
REPO_ROOT = Path(os.environ.get("CONFIG_PUSH_REPO_ROOT") or Path(__file__).resolve().parents[3])
WORKSPACE = Path(os.environ.get("CONFIG_PUSH_WORKSPACE") or REPO_ROOT)
LINKS_CONFIG = WORKSPACE / "links_config.json"
LOCAL_SECRETS = WORKSPACE / "一键推送配置.local.json"
# 生产公钥单一真相来源：编译进客户端的 shared/perf_pubkey.h（不依赖任何 *.pem，避免错配）
PERF_PUBKEY_H = REPO_ROOT / "shared" / "perf_pubkey.h"

CF_BASE = "https://v653tjh4t413yt76.dpdns.org"
RAW_BASE = "https://raw.githubusercontent.com"

# 非密默认值（标识，可被 env / local 覆盖）
_DEFAULTS = {
    "github_owner": "chbengbu10086",
    "github_repo": "cloud-issuer",
    "cf_account_id": "333424ca65a4eb60288ba0b857c005c6",
    "cf_kv_id": "2eb5cba618f84b12b8847803c68864de",
    "private_key_path": "reference/cloud_issuer_secrets/private.pem",
}

_ENV_MAP = {
    "github_owner": "GITHUB_OWNER",
    "github_repo": "GITHUB_REPO",
    "github_pat": "GITHUB_PAT",
    "cf_account_id": "CF_ACCOUNT_ID",
    "cf_api_token": "CF_API_TOKEN",
    "cf_kv_id": "CF_KV_ID",
    "private_key_path": "PRIVATE_KEY_PATH",
}


def _read_local_secrets() -> dict:
    if not LOCAL_SECRETS.exists():
        return {}
    try:
        data = json.loads(LOCAL_SECRETS.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:  # noqa: BLE001
        print(f"[警告] 读取本地凭证文件失败: {e}", file=sys.stderr)
        return {}


def _resolve_cred(name: str) -> str:
    env_name = _ENV_MAP.get(name)
    if env_name and os.environ.get(env_name, "").strip():
        return os.environ[env_name].strip()
    local = _read_local_secrets()
    if name in local and str(local[name]).strip():
        return str(local[name]).strip()
    return _DEFAULTS.get(name, "")


def _load_private_key():
    pem = os.environ.get("RSA_PRIVATE_KEY", "").strip()
    if pem:
        return _load_private_key_from_string(pem)
    path = _resolve_cred("private_key_path")
    if path:
        p = Path(path)
        if not p.is_absolute():
            p = REPO_ROOT / p
        if p.exists():
            return _load_private_key_from_file(p)
    raise RuntimeError("未找到 RSA 私钥：请设置 RSA_PRIVATE_KEY 环境变量或 private_key_path")


def _load_production_public_key():
    """从 shared/perf_pubkey.h 提取编译进客户端的生产公钥（294 字节 DER）。"""
    src = PERF_PUBKEY_H.read_text(encoding="utf-8")
    m = re.search(r"PERF_PUBKEY_DER\[\d+\]\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        raise RuntimeError(f"无法从 {PERF_PUBKEY_H} 提取生产公钥数组")
    der = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
    if len(der) != 294:
        raise RuntimeError(f"生产公钥 DER 长度异常: {len(der)}（应为 294）")
    return serialization.load_der_public_key(der)


def serialize_config(cfg: dict) -> bytes:
    """把 config 对象确定性序列化成 key=value 纯文本（键排序，UTF-8，末尾换行）。"""
    if not isinstance(cfg, dict) or not cfg:
        raise ValueError("配置对象为空或非法")
    lines = []
    for k in sorted(cfg.keys()):
        v = cfg[k]
        if not isinstance(v, str):
            raise ValueError(f"字段 {k} 必须是字符串")
        v = v.strip()
        if not v:
            raise ValueError(f"字段 {k} 值为空")
        if "\r" in v or "\n" in v:
            raise ValueError(f"字段 {k} 含换行符")
        if not v.startswith("https://"):
            raise ValueError(f"字段 {k} 必须以 https:// 开头")
        lines.append(f"{k}={v}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _verify_sig(pub, raw: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, raw, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------- GitHub Git Data API ----------
def _gh_headers(pat: str) -> dict:
    return {
        "Authorization": f"token {pat}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "config-pusher",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _gh_json(r, what: str):
    if r.status_code not in (200, 201):
        raise RuntimeError(f"GitHub {what} 失败 ({r.status_code}): {r.text[:500]}")
    return r.json()


def github_push(owner: str, repo: str, pat: str, files: dict, branch: str = "main",
                message: str = "chore(config): update config") -> str:
    """把 files（{路径: bytes}）原子提交到 main 分支（单个 commit 含全部文件）。"""
    api = "https://api.github.com"
    h = _gh_headers(pat)

    ref = _gh_json(requests.get(f"{api}/repos/{owner}/{repo}/git/ref/heads/{branch}",
                                headers=h, timeout=30), "获取分支")
    base_sha = ref["object"]["sha"]
    base_commit = _gh_json(requests.get(f"{api}/repos/{owner}/{repo}/git/commits/{base_sha}",
                                        headers=h, timeout=30), "获取基础提交")
    base_tree_sha = base_commit["tree"]["sha"]

    tree_items = []
    for path, content_bytes in files.items():
        b64 = base64.b64encode(content_bytes).decode("ascii")
        blob = _gh_json(requests.post(f"{api}/repos/{owner}/{repo}/git/blobs", headers=h,
                                      timeout=30, json={"content": b64, "encoding": "base64"}),
                        f"创建 blob {path}")
        tree_items.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})

    tree = _gh_json(requests.post(f"{api}/repos/{owner}/{repo}/git/trees", headers=h, timeout=30,
                                  json={"base_tree": base_tree_sha, "tree": tree_items}),
                    "创建 tree")
    commit = _gh_json(requests.post(f"{api}/repos/{owner}/{repo}/git/commits", headers=h, timeout=30,
                                    json={"message": message, "tree": tree["sha"],
                                          "parents": [base_sha]}),
                      "创建 commit")
    _gh_json(requests.patch(f"{api}/repos/{owner}/{repo}/git/refs/heads/{branch}", headers=h,
                            timeout=30, json={"sha": commit["sha"], "force": False}),
             "更新分支 ref")
    return commit["sha"]


# ---------- Cloudflare KV REST API ----------
def cf_kv_put(account_id: str, token: str, kv_id: str, key: str, value: str) -> None:
    url = (f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
           f"/storage/kv/namespaces/{kv_id}/values/{key}")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "text/plain"}
    r = requests.put(url, headers=headers, data=value.encode("utf-8"), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"CF KV 写入 {key} 失败 ({r.status_code}): {r.text[:500]}")
    j = r.json()
    if not j.get("success"):
        raise RuntimeError(f"CF KV 写入 {key} 返回 success=false: {j.get('errors')}")


# ---------- 回访验证 ----------
def _verify_github(pub, owner: str, repo: str, pat: str, cid: int, expected: bytes) -> bool:
    """通过 GitHub API 立即验证 main 分支 config/config_N.{txt,sig}（不受 raw CDN 延迟影响）。"""
    api = "https://api.github.com"
    h = {"Accept": "application/vnd.github+json"}
    if pat:
        h["Authorization"] = f"token {pat}"
    try:
        txt = requests.get(f"{api}/repos/{owner}/{repo}/contents/config/config_{cid}.txt",
                           headers=h, timeout=30)
        sig = requests.get(f"{api}/repos/{owner}/{repo}/contents/config/config_{cid}.sig",
                           headers=h, timeout=30)
        if txt.status_code != 200 or sig.status_code != 200:
            return False
        txt_bytes = base64.b64decode(txt.json().get("content", ""))
        sig_bytes = base64.b64decode(sig.json().get("content", ""))
        return txt_bytes == expected and _verify_sig(pub, txt_bytes, sig_bytes)
    except requests.RequestException:
        return False


def _verify_cf(pub, cid: int) -> bool:
    """验签 CF /config 响应（验签通过即证明通道可用；内容为部署态，KV 内容需重新部署后生效）。"""
    url = f"{CF_BASE}/config?id={cid}"
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            return False
        sig = base64.b64decode(r.headers.get("X-Config-Sign", "") or "")
        return _verify_sig(pub, r.content, sig)
    except requests.RequestException:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="一键推送配置到 CF KV + GitHub main")
    p.add_argument("--id", type=int, default=None, help="推送指定 config id；缺省用 active_config_id")
    p.add_argument("--all", action="store_true", help="推送所有 config")
    p.add_argument("--dry-run", action="store_true", help="只签名并本地自验，不推送")
    p.add_argument("--verify-only", action="store_true", help="只回访验证，不签名不推送")
    args = p.parse_args(argv)

    if not LINKS_CONFIG.exists():
        print(f"[错误] 找不到 {LINKS_CONFIG}")
        return 1
    data = json.loads(LINKS_CONFIG.read_text(encoding="utf-8"))
    configs = data.get("configs", {})
    active = data.get("active_config_id", 1)

    if args.all:
        ids = sorted(int(k) for k in configs.keys())
    elif args.id is not None:
        ids = [args.id]
    else:
        ids = [int(active)]

    owner = _resolve_cred("github_owner")
    repo = _resolve_cred("github_repo")
    pat = _resolve_cred("github_pat")
    account_id = _resolve_cred("cf_account_id")
    api_token = _resolve_cred("cf_api_token")
    kv_id = _resolve_cred("cf_kv_id")

    if not args.verify_only:
        missing = [n for n, v in (("github_pat", pat), ("cf_api_token", api_token)) if not v]
        if missing:
            print(f"[错误] 缺少凭证: {', '.join(missing)}（请设置环境变量或 {LOCAL_SECRETS.name}）")
            return 1
        private_key = _load_private_key()

    pub = _load_production_public_key()

    for cid in ids:
        cfg = configs.get(str(cid))
        if cfg is None:
            print(f"[跳过] config {cid} 不存在")
            continue
        try:
            raw = serialize_config(cfg)
        except ValueError as e:
            print(f"[错误] config {cid}: {e}")
            return 1

        print(f"\n===== config {cid} =====")
        print(raw.decode("utf-8"))

        sig = None
        if not args.verify_only:
            sig = sign_config_bytes(raw, private_key)
            sig_b64 = base64.b64encode(sig).decode("ascii")
            if not _verify_sig(pub, raw, sig):
                print("[错误] 本地自验失败，坏签名绝不上云")
                return 1
            print(f"[自验] OK（{len(sig)} 字节签名）")

            if args.dry_run:
                print("[dry-run] 已跳过推送")
                continue

            try:
                commit_sha = github_push(owner, repo, pat, {
                    f"config/config_{cid}.txt": raw,
                    f"config/config_{cid}.sig": sig,
                }, branch="main", message=f"chore(config): update config_{cid}")
                print(f"[GitHub] 已提交 {commit_sha}")
            except Exception as e:  # noqa: BLE001
                print(f"[GitHub] 推送失败: {e}")
                return 1

            try:
                cf_kv_put(account_id, api_token, kv_id, f"config_{cid}", raw.decode("utf-8"))
                cf_kv_put(account_id, api_token, kv_id, f"config_{cid}_sig", sig_b64)
                print(f"[CF KV] 已写入 config_{cid} / config_{cid}_sig")
            except Exception as e:  # noqa: BLE001
                print(f"[CF KV] 写入失败: {e}")
                return 1

        print("[验证] 正在回访两端...")
        gha_ok = _verify_github(pub, owner, repo, pat, cid, raw)
        cf_ok = _verify_cf(pub, cid)
        print(f"[验证] GitHub (API): {'OK' if gha_ok else '失败'} → main:config/config_{cid}.txt")
        print(f"[验证] GitHub raw (客户端实际拉取): {RAW_BASE}/{owner}/{repo}/config/config_{cid}.txt（raw CDN 有分钟级延迟）")
        print(f"[验证] Cloudflare: {'OK(验签通过)' if cf_ok else '失败'} → {CF_BASE}/config?id={cid}")
        if not cf_ok:
            print("[提示] Cloudflare 验签失败：检查 Worker 是否已部署新 index.js + wrangler.toml KV 绑定。")

    print("\n完成。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
