from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol

from .config import Config


class Storage(Protocol):
    """put/get はストレージとローカルファイルの転送。url() はカタログに登録する絶対参照。"""

    def put(self, local_path: Path, key: str) -> None: ...
    def get(self, key: str, local_path: Path) -> bool: ...
    def exists(self, key: str) -> bool: ...
    def list(self, prefix: str) -> list[str]: ...
    def url(self, key: str) -> str: ...


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, local_path: Path, key: str) -> None:
        dest = self._path(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_path, dest)

    def get(self, key: str, local_path: Path) -> bool:
        src = self._path(key)
        if not src.exists():
            return False
        local_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, local_path)
        return True

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def list(self, prefix: str) -> list[str]:
        if not self.root.exists():
            return []
        keys = (
            str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file()
        )
        return sorted(k for k in keys if k.startswith(prefix))

    def url(self, key: str) -> str:
        return str(self._path(key).resolve())


class S3Storage:
    def __init__(self, bucket: str, endpoint: str | None, public_url: str):
        import boto3

        self.client = boto3.client("s3", endpoint_url=endpoint)
        self.bucket = bucket
        self.public_url = public_url

    def put(self, local_path: Path, key: str) -> None:
        self.client.upload_file(str(local_path), self.bucket, key)

    def get(self, key: str, local_path: Path) -> bool:
        import botocore.exceptions

        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.client.download_file(self.bucket, key, str(local_path))
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise
        return True

    def exists(self, key: str) -> bool:
        import botocore.exceptions

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise
        return True

    def list(self, prefix: str) -> list[str]:
        paginator = self.client.get_paginator("list_objects_v2")
        keys: list[str] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            keys.extend(obj["Key"] for obj in page.get("Contents", []))
        return sorted(keys)

    def url(self, key: str) -> str:
        return f"{self.public_url}/{key}"


def make_storage(cfg: Config) -> Storage:
    if cfg.s3_bucket:
        if cfg.public_url is None:
            raise ValueError("public_url が未設定 (Config.from_env が保証する不変条件)")
        return S3Storage(cfg.s3_bucket, cfg.s3_endpoint, cfg.public_url)
    if cfg.local_dir is None:
        raise ValueError("local_dir が未設定 (Config.from_env が保証する不変条件)")
    return LocalStorage(cfg.local_dir)
