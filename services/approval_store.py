"""Retain exact approved commands behind bounded, org-scoped references."""

import json
import re
from typing import Optional
from uuid import uuid4

from services.org_context import current_org_id
from storage import factory
from storage.base import StorageProvider

APPROVAL_REFERENCE_PREFIX = "agent-approval:"


class CommandApprovalStore:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or factory.get_storage()

    def retain(self, command: str, host: Optional[str] = None) -> str:
        """Retain the complete executable command; bound only its display label."""
        org_id = current_org_id()
        identifier = uuid4().hex
        target_label = json.dumps(str(host or "localhost")[:128])
        reference = f"{APPROVAL_REFERENCE_PREFIX}{identifier} ({target_label})"
        key = self.storage.org_prefix(org_id, "approvals", f"{identifier}.json")
        created = self.storage.put_json_if_absent(
            key,
            {
                "org_id": org_id,
                "reference": reference,
                "command": command,
                "host": host,
            },
        )
        if not created:
            raise RuntimeError("Approval reference already exists")
        return reference

    def resolve(self, reference: str) -> Optional[str]:
        """Resolve only an exact reference belonging to the current organisation."""
        if not reference.startswith(APPROVAL_REFERENCE_PREFIX):
            return None
        identifier = reference[len(APPROVAL_REFERENCE_PREFIX) :].split(" ", 1)[0]
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            return None
        org_id = current_org_id()
        key = self.storage.org_prefix(org_id, "approvals", f"{identifier}.json")
        record = self.storage.get_json(key)
        if not isinstance(record, dict):
            return None
        if record.get("org_id") != org_id or record.get("reference") != reference:
            return None
        command = record.get("command")
        return command if isinstance(command, str) and command else None
