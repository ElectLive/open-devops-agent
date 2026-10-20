"""Retain exact approved commands behind bounded, org-scoped references."""

import json
import re
import time
from typing import Optional
from uuid import uuid4

from services.org_context import current_org_id
from storage import factory
from storage.base import StorageProvider
from storage.azure_storage import AzureBlobStorage
from storage.gcs_storage import GCSStorage
from storage.memory_storage import MemoryStorage
from storage.s3_storage import S3Storage

APPROVAL_REFERENCE_PREFIX = "agent-approval:"
APPROVAL_TTL_SECONDS = 3600
APPROVALS_PER_WINDOW = 256
MAX_APPROVAL_RECORD_BYTES = 256 * 1024


class CommandApprovalStore:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or factory.get_storage()

    def _create_atomically(self, key: str, record: dict) -> bool:
        if isinstance(self.storage, S3Storage):
            # Approval claims must never use S3Storage's compatibility fallback,
            # which checks existence before writing and cannot serialize claims.
            from botocore.exceptions import ClientError, ParamValidationError

            try:
                self.storage._client.put_object(
                    Bucket=self.storage.bucket,
                    Key=key,
                    Body=json.dumps(record, indent=2).encode(),
                    ContentType="application/json",
                    IfNoneMatch="*",
                )
                return True
            except ParamValidationError as exc:
                raise RuntimeError(
                    "Approval storage requires atomic conditional writes"
                ) from exc
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in {
                    "PreconditionFailed",
                    "ConditionalRequestConflict",
                }:
                    return False
                raise
        if type(self.storage).put_json_if_absent is StorageProvider.put_json_if_absent:
            raise RuntimeError("Approval storage requires atomic conditional writes")
        return self.storage.put_json_if_absent(key, record)

    def _prefix(self) -> str:
        return self.storage.org_prefix(current_org_id(), "approvals") + "/"

    def _replace_s3(self, key: str, record: dict, etag: str) -> bool:
        """Replace an existing object version; never create a missing object."""
        from botocore.exceptions import ClientError, ParamValidationError

        try:
            self.storage._client.put_object(
                Bucket=self.storage.bucket,
                Key=key,
                Body=json.dumps(record, indent=2).encode(),
                ContentType="application/json",
                IfMatch=etag,
            )
            return True
        except ParamValidationError as exc:
            raise RuntimeError(
                "Approval storage requires atomic conditional replacement"
            ) from exc
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {
                "PreconditionFailed",
                "ConditionalRequestConflict",
                "NoSuchKey",
                "404",
            }:
                return False
            raise

    def _consume_existing(self, key: str, expected: dict) -> bool:
        """Grant execution only by atomically consuming the current payload.

        Cached data and a missing claim marker convey no authority. Cloud
        replacement requires the version of a still-existing matching payload;
        deleting the resulting terminal record cannot restore that version.
        """
        if isinstance(self.storage, MemoryStorage):
            with self.storage._lock:
                raw = self.storage._objects.get(key)
                if raw is None or json.loads(raw) != expected:
                    return False
                del self.storage._objects[key]
                return True

        terminal = {"consumed": True, "expires_at": expected["expires_at"]}
        if isinstance(self.storage, S3Storage):
            from botocore.exceptions import ClientError

            try:
                response = self.storage._client.get_object(
                    Bucket=self.storage.bucket, Key=key
                )
                if json.loads(response["Body"].read()) != expected:
                    return False
                return self._replace_s3(key, terminal, response["ETag"])
            except self.storage._client.exceptions.NoSuchKey:
                return False
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                    return False
                raise

        if isinstance(self.storage, GCSStorage):
            from google.api_core.exceptions import NotFound, PreconditionFailed

            try:
                blob = self.storage._bucket.blob(key)
                blob.reload()
                generation = blob.generation
                if not generation:
                    raise RuntimeError(
                        "Approval storage requires an existing object generation"
                    )
                raw = blob.download_as_bytes(if_generation_match=generation)
                if json.loads(raw) != expected:
                    return False
                blob.upload_from_string(
                    json.dumps(terminal),
                    content_type="application/json",
                    if_generation_match=generation,
                )
                return True
            except (NotFound, PreconditionFailed):
                return False

        if isinstance(self.storage, AzureBlobStorage):
            from azure.core import MatchConditions
            from azure.core.exceptions import (
                ResourceModifiedError,
                ResourceNotFoundError,
            )

            try:
                blob = self.storage._container_client.get_blob_client(key)
                etag = blob.get_blob_properties().etag
                if not etag:
                    raise RuntimeError(
                        "Approval storage requires an existing object ETag"
                    )
                raw = blob.download_blob(
                    etag=etag, match_condition=MatchConditions.IfNotModified
                ).readall()
                if json.loads(raw) != expected:
                    return False
                blob.upload_blob(
                    json.dumps(terminal).encode(),
                    overwrite=True,
                    etag=etag,
                    match_condition=MatchConditions.IfNotModified,
                )
                return True
            except (ResourceModifiedError, ResourceNotFoundError):
                return False
        raise RuntimeError(
            "Approval storage requires atomic consumption of existing state"
        )

    def cleanup(self) -> None:
        """Reclaim expired payloads/claims and old admission slots on access."""
        now = time.time()
        oldest_window = int(now) // APPROVAL_TTL_SECONDS - 1
        prefix = self._prefix()
        for key in self.storage.list_keys(prefix):
            relative = key[len(prefix) :]
            # Untimed records from the old adapter cannot safely authorize work.
            expired = bool(re.fullmatch(r"[0-9a-f]{32}\.json", relative))
            match = re.fullmatch(
                r"v2/([0-9a-f]{8})/[0-9a-f]{4}/(reserved\.json|[0-9a-f]{32}\.(?:json|claim))",
                relative,
            )
            if match:
                filename = match.group(2)
                expired = int(match.group(1), 16) < oldest_window or (
                    filename != "reserved.json" and int(filename[:8], 16) <= now
                )
            if expired:
                removed = self.storage.delete(key)
                if not removed and self.storage.exists(key):
                    raise RuntimeError(
                        "Approval cleanup failed; refusing additional retained state"
                    )

    def retain(self, command: str, host: Optional[str] = None) -> str:
        """Admit a bounded, expiring operation without reusing a live slot."""
        self.cleanup()
        org_id = current_org_id()
        created_at = int(time.time())
        expires_at = created_at + APPROVAL_TTL_SECONDS
        window = created_at // APPROVAL_TTL_SECONDS
        target_label = json.dumps(str(host or "localhost")[:128])
        for slot in range(APPROVALS_PER_WINDOW):
            identifier = f"{expires_at:08x}{slot:04x}{uuid4().hex[:20]}"
            reference = f"{APPROVAL_REFERENCE_PREFIX}{identifier} ({target_label})"
            record = {
                "org_id": org_id,
                "reference": reference,
                "command": command,
                "host": host,
                "created_at": created_at,
                "expires_at": expires_at,
            }
            if len(json.dumps(record, indent=2).encode()) > MAX_APPROVAL_RECORD_BYTES:
                raise ValueError("Approval record exceeds the retained size limit")
            prefix = f"{self._prefix()}v2/{window:08x}/{slot:04x}/"
            if not self._create_atomically(
                prefix + "reserved.json", {"expires_at": expires_at}
            ):
                continue
            key = prefix + identifier + ".json"
            if isinstance(self.storage, S3Storage):
                # Some compatible servers accept If-Match on an absent key.
                # Verify this essential fencing precondition before retaining
                # executable content; a successful missing-key write is unsafe.
                if self._replace_s3(
                    key, {"expires_at": expires_at}, '"' + "0" * 32 + '"'
                ):
                    self.storage.delete(key)
                    raise RuntimeError(
                        "Approval storage lacks atomic existing-object replacement"
                    )
            self.storage.put_json(key, record)
            if time.time() >= expires_at:
                self.storage.delete(key)
                raise RuntimeError("Approval expired during retention")
            return reference
        raise RuntimeError(
            "Approval capacity exhausted; request a new approval in the next window"
        )

    def resolve(self, reference: str) -> Optional[str]:
        """Atomically spend a matching, unexpired reference before execution.

        A failed execution also spends the reference. Consumption requires
        authoritative payload state, independently of wall clocks and cleanup.
        """
        self.cleanup()
        if not reference.startswith(APPROVAL_REFERENCE_PREFIX):
            return None
        identifier = reference[len(APPROVAL_REFERENCE_PREFIX) :].split(" ", 1)[0]
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            return None
        expires_at = int(identifier[:8], 16)
        if time.time() >= expires_at:
            return None
        org_id = current_org_id()
        window = (expires_at - APPROVAL_TTL_SECONDS) // APPROVAL_TTL_SECONDS
        slot = int(identifier[8:12], 16)
        prefix = f"{self._prefix()}v2/{window:08x}/{slot:04x}/"
        key = prefix + identifier + ".json"
        record = self.storage.get_json(key)
        if not isinstance(record, dict):
            return None
        if (
            record.get("org_id") != org_id
            or record.get("reference") != reference
            or record.get("expires_at") != expires_at
        ):
            return None
        command = record.get("command")
        if not isinstance(command, str) or not command:
            return None
        if not self._consume_existing(key, record):
            return None
        # A caller may have paused across expiry before consuming the payload.
        if time.time() >= expires_at:
            self.storage.delete(key)
            return None
        self.storage.delete(key)
        return command
