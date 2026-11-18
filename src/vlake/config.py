from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def validate_public_url(public_url: str) -> None:
    try:
        parsed = urlsplit(public_url)
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and not any(char.isspace() for char in public_url)
            and parsed.username is None
            and parsed.password is None
            and (parsed.port is None or parsed.port > 0)
            and "?" not in public_url
            and "#" not in public_url
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(
            "VLAKE_PUBLIC_URL は空白・認証情報・クエリ・フラグメントを含まず、"
            "ホスト名と妥当なポート（指定時）を持つ公開 HTTPS ベース URL にしてください"
        )


@dataclass(frozen=True)
class Config:
    s3_endpoint: str | None
    s3_bucket: str | None
    public_url: str | None
    local_dir: Path | None

    @classmethod
    def from_env(cls) -> Config:
        bucket = os.environ.get("VLAKE_S3_BUCKET")
        local = os.environ.get("VLAKE_LOCAL_DIR")
        public = (os.environ.get("VLAKE_PUBLIC_URL") or "").rstrip("/") or None
        if not bucket and not local:
            raise SystemExit(
                "VLAKE_S3_BUCKET (S3互換) または VLAKE_LOCAL_DIR (ローカル) を設定してください"
            )
        if bucket and not public:
            raise SystemExit(
                "VLAKE_PUBLIC_URL (カタログに焼き込む公開HTTPSベースURL) が必要です"
            )
        if bucket:
            try:
                validate_public_url(public)
            except ValueError as exc:
                raise SystemExit(str(exc)) from None
        return cls(
            s3_endpoint=os.environ.get("VLAKE_S3_ENDPOINT"),
            s3_bucket=bucket,
            public_url=public,
            local_dir=Path(local) if local else None,
        )
