from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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
        return cls(
            s3_endpoint=os.environ.get("VLAKE_S3_ENDPOINT"),
            s3_bucket=bucket,
            public_url=public,
            local_dir=Path(local) if local else None,
        )
