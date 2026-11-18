"""Config signing script — 离线对配置文本签名，产出 config_N.sig 供 GHA 备用通道使用。

与 license 签发不同：config 下发采用「原文字节签名、客户端原样验签」，绝不做 canonical
序列化。因此本脚本直接对 config_N.txt 的原始字节做 RSA-2048 PKCS#1 v1.5 + SHA-256 签名，
输出 256 字节原始签名到 config_N.sig。

签名密钥与 license 签发（sign_license.py）共用同一把生产 RSA 私钥（RSA_PRIVATE_KEY），
客户端用内置 perf_pubkey 验签，信任根统一。

用法：
  离线文件密钥：
    python sign_config.py --id 1 --config-dir ./config --private-key path/to/priv.pem
  环境变量密钥（GHA Secrets 场景）：
    RSA_PRIVATE_KEY=... python sign_config.py --id 1 --config-dir ./config

产物：config/config_1.txt（输入原文）+ config/config_1.sig（256 字节原始签名）。
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIG_LEN = 256  # RSA-2048


def _load_private_key_from_string(pem_text: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    return key


def _load_private_key_from_file(path: str | Path) -> rsa.RSAPrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    return key


def sign_config_bytes(raw: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """对配置原文原始字节做 PKCS#1 v1.5 + SHA-256 签名，返回 256 字节。"""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    sig = private_key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
    if len(sig) != SIG_LEN:
        raise RuntimeError(f"unexpected signature length: {len(sig)} (want {SIG_LEN})")
    return sig


def main() -> None:
    p = argparse.ArgumentParser(description="签名配置文本，产出 config_N.sig")
    p.add_argument("--id", type=int, required=True, help="ACTIVE_CONFIG_ID")
    p.add_argument("--config-dir", default="./config", help="config_N.txt 所在目录")
    p.add_argument("--private-key", help="PEM 私钥文件路径；缺省则读 RSA_PRIVATE_KEY 环境变量")
    args = p.parse_args()

    config_dir = Path(args.config_dir)
    txt_path = config_dir / f"config_{args.id}.txt"
    sig_path = config_dir / f"config_{args.id}.sig"

    raw = txt_path.read_bytes()

    if args.private_key:
        private_key = _load_private_key_from_file(args.private_key)
    else:
        pem = os.environ.get("RSA_PRIVATE_KEY")
        if not pem:
            raise RuntimeError("env RSA_PRIVATE_KEY not set — did you wire Secrets?")
        private_key = _load_private_key_from_string(pem)

    sig = sign_config_bytes(raw, private_key)
    sig_path.write_bytes(sig)

    print(f"OK: {sig_path} ({len(sig)} bytes) signed from {txt_path}")


if __name__ == "__main__":
    main()
