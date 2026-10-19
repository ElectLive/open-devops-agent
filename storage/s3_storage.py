"""S3-compatible storage — AWS S3 and MinIO."""
from __future__ import annotations

import json
import os
from typing import Any, List, Optional

from storage.base import StorageProvider


class S3Storage(StorageProvider):
    def __init__(
        self,
        bucket: str,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
    ):
        import boto3
        from botocore.config import Config

        self.bucket = bucket
        kwargs = {"region_name": region or os.getenv("AWS_REGION", "us-east-1")}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key

        self._client = boto3.client("s3", config=Config(signature_version="s3v4"), **kwargs)
        self._ensure_bucket(region or os.getenv("AWS_REGION", "us-east-1"), endpoint_url is not None)

    def _ensure_bucket(self, region: str, is_custom_endpoint: bool):
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except Exception:
            try:
                if is_custom_endpoint or region == "us-east-1":
                    self._client.create_bucket(Bucket=self.bucket)
                else:
                    self._client.create_bucket(
                        Bucket=self.bucket,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
            except Exception:
                pass  # Bucket may already exist or be created externally

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        self._client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type)
        return key

    def put_json(self, key: str, data: Any) -> str:
        return self.put_bytes(key, json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json")

    def put_json_if_absent(self, key: str, data: Any) -> bool:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        try:
            from botocore.exceptions import ClientError, ParamValidationError
        except ImportError:
            return super().put_json_if_absent(key, data)
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                IfNoneMatch="*",
            )
            return True
        except ParamValidationError:
            return super().put_json_if_absent(key, data)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"PreconditionFailed", "ConditionalRequestConflict"}:
                return False
            raise

    def get_bytes(self, key: str) -> Optional[bytes]:
        try:
            resp = self._client.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except self._client.exceptions.NoSuchKey:
            return None
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                return None
            raise

    def get_json(self, key: str) -> Optional[Any]:
        raw = self.get_bytes(key)
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    def list_keys(self, prefix: str) -> List[str]:
        keys: List[str] = []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
        return sorted(keys)

    def delete(self, key: str) -> bool:
        if not self.exists(key):
            return False
        self._client.delete_object(Bucket=self.bucket, Key=key)
        return True

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False
