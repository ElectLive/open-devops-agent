"""
Security controls — emergency stop, webhook auth, Slack signatures, SSH hardening.
"""
import hashlib
import hmac
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.webhook_auth import (
    verify_hmac_sha256_signature,
    verify_slack_signature,
    verify_webhook_request,
)
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from storage.memory_storage import MemoryStorage
from tools.executor import SafeExecutor
from tools.safety import requires_configured_approval
from tools.ssh_utils import build_ssh_command

# Header values reach the application latin-1-decoded, so an unauthenticated
# caller can put non-ASCII characters into a signature header.
NON_ASCII_WEBHOOK_SIGNATURE = "sha256=\xff\xfe"
NON_ASCII_SLACK_SIGNATURE = "v0=\xff\xfe"

# Well-formed (hex, right length) but not the expected digest.
WRONG_WEBHOOK_SIGNATURE = "sha256=" + "0" * 64
WRONG_SLACK_SIGNATURE = "v0=" + "0" * 64


class TestEmergencyStop:
    @pytest.mark.asyncio
    async def test_blocks_mutating_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run_safe("kubectl rollout restart deployment/api")
        assert result.get("emergency_stop") is True
        assert result.get("blocked") is True

    @pytest.mark.asyncio
    async def test_allows_read_only_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        with patch("asyncio.create_subprocess_shell") as mock_proc:
            mock_proc.return_value = AsyncMock(
                returncode=0,
                communicate=AsyncMock(return_value=(b"ok", b"")),
            )
            result = await executor.run_safe("kubectl get pods")
            assert result.get("success") is True

    @pytest.mark.asyncio
    async def test_blocks_approved_run_during_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run("systemctl restart nginx")
        assert result.get("emergency_stop") is True


class TestRequireApprovalFor:
    def test_rollback_requires_approval(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "rollback")
        assert requires_configured_approval("kubectl rollout undo deployment/api") is True

    def test_unlisted_action_not_forced(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "delete")
        assert requires_configured_approval("systemctl restart nginx") is False


class TestWebhookAuth:
    def test_valid_hmac_signature(self):
        secret = "test-secret"
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_hmac_sha256_signature(payload, sig, secret) is True

    def test_rejects_invalid_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "secret")
        assert verify_webhook_request(b"{}", "sha256=deadbeef") is False

    def test_skips_when_no_secret_configured(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
        assert verify_webhook_request(b"{}", None) is True

    # Fail-closed invariant: any signature that is not a byte-for-byte match of the
    # expected signature must be rejected — malformed, empty, absent or simply
    # incorrect. No input turns a rejection into an acceptance, and none raises.

    def test_rejects_non_ascii_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", NON_ASCII_WEBHOOK_SIGNATURE) is False

    def test_rejects_non_ascii_signature_in_hmac_helper(self):
        payload = b'{"type":"server"}'
        assert (
            verify_hmac_sha256_signature(payload, NON_ASCII_WEBHOOK_SIGNATURE, "test-secret")
            is False
        )

    def test_rejects_empty_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", "") is False

    def test_rejects_absent_signature_when_secret_configured(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", None) is False

    def test_accepts_correct_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not break the accept path."""
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_webhook_request(payload, sig) is True

    def test_rejects_incorrect_but_well_formed_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b'{"type":"server"}', WRONG_WEBHOOK_SIGNATURE) is False

    def test_accepts_gitlab_static_token(self, monkeypatch):
        from api.webhook_auth import verify_webhook_auth

        monkeypatch.setenv("WEBHOOK_SECRET", "gitlab-secret")
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="gitlab-secret") is True
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="wrong") is False
        assert verify_webhook_auth(b"{}", signature=None, static_token=None) is False


class TestSlackSignature:
    def test_valid_slack_signature(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()))
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is True

    def test_rejects_stale_timestamp(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()) - 600)
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is False

    # Same fail-closed invariant as TestWebhookAuth. The accept path is guarded by
    # test_valid_slack_signature above, which must keep passing.

    def test_rejects_non_ascii_signature(self):
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, NON_ASCII_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_empty_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, "", "slack-secret") is False

    def test_rejects_absent_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, None, "slack-secret") is False

    def test_rejects_incorrect_but_well_formed_signature(self):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_non_utf8_body(self):
        """A body that is not UTF-8 must be rejected, not decoded lossily and not raise."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(b"\xff\xfe", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret")
            is False
        )


class TestSshUtils:
    def test_strict_host_key_checking_by_default(self, monkeypatch):
        monkeypatch.delenv("SSH_STRICT_HOST_KEY_CHECKING", raising=False)
        cmd = build_ssh_command("10.0.0.5", "df -h")
        assert "StrictHostKeyChecking=yes" in cmd
        assert "StrictHostKeyChecking=no" not in cmd

    def test_applies_remote_user(self, monkeypatch):
        monkeypatch.setenv("SSH_REMOTE_USER", "ubuntu")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "ubuntu@10.0.0.5" in cmd

    def test_allows_opt_out_for_dev(self, monkeypatch):
        monkeypatch.setenv("SSH_STRICT_HOST_KEY_CHECKING", "false")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "StrictHostKeyChecking=no" in cmd


class TestWebhookEndpoints:
    def test_manual_webhook_requires_signature_when_secret_set(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        from api.server import app

        client = TestClient(app)
        response = client.post(
            "/webhook/manual",
            json={"type": "server", "description": "test"},
        )
        assert response.status_code == 401

    def test_manual_webhook_accepts_valid_signature(self, monkeypatch):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        payload = {"type": "server", "description": "test"}
        body = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        with patch("api.server.enqueue_incident", new=AsyncMock(return_value="INC-1")):
            response = client.post(
                "/webhook/manual",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": sig,
                },
            )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_health_reports_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        from api.server import app

        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["emergency_stop"] is True

    @pytest.mark.parametrize(
        "path",
        [
            "/webhook/github",
            "/webhook/alertmanager",
            "/webhook/gitlab",
            "/webhook/bitbucket",
            "/webhook/manual",
        ],
    )
    def test_webhook_malformed_json_returns_400(self, monkeypatch, path):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        body = b"not json"
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        response = client.post(
            path,
            content=body,
            headers={"X-Hub-Signature-256": sig},
        )
        assert response.status_code == 400

    @pytest.mark.parametrize(
        "path",
        [
            "/webhook/github",
            "/webhook/alertmanager",
            "/webhook/gitlab",
            "/webhook/bitbucket",
            "/webhook/manual",
        ],
    )
    def test_webhook_non_object_json_returns_400(self, monkeypatch, path):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        body = b"null"
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        response = client.post(
            path,
            content=body,
            headers={"X-Hub-Signature-256": sig},
        )
        assert response.status_code == 400


@pytest.fixture
def bitbucket_request(monkeypatch):
    from api.server import app

    signing_key = os.urandom(32)
    monkeypatch.setenv("WEBHOOK_SECRET", signing_key.hex())

    def post(
        payload,
        event="pullrequest:created",
        org_id="tenant-ember",
        raise_server_exceptions=True,
    ):
        body = json.dumps(payload).encode()
        signature = "sha256=" + hmac.new(
            signing_key.hex().encode(), body, hashlib.sha256
        ).hexdigest()
        headers = {"X-Hub-Signature-256": signature, "X-Org-ID": org_id}
        if event is not None:
            headers["X-Event-Key"] = event
        return TestClient(app, raise_server_exceptions=raise_server_exceptions).post(
            "/webhook/bitbucket", content=body, headers=headers
        )

    return post


@pytest.fixture
def bitbucket_payload():
    return {
        "repository": {
            "workspace": {"slug": "workspace-cedar"},
            "slug": "repository-maple",
        },
        "pullrequest": {
            "id": 731,
            "title": "Review this change",
            "source": {
                "branch": {"name": "feature"},
                "commit": {"hash": "commit-juniper"},
            },
            "destination": {"branch": {"name": "main"}},
        },
    }


@pytest.fixture
def review_queue(monkeypatch):
    queue = IncidentQueue(MemoryStorage())
    monkeypatch.setattr("api.server.incident_queue", queue)
    return queue


class InterruptedQueueWrite(BaseException):
    """Simulate a stop that bypasses normal exception cleanup."""


@pytest.fixture
def review_context():
    return {
        "type": "code_review",
        "scm_platform": "bitbucket",
        "repo": "workspace-cedar/repository-maple",
        "change_id": "731",
        "head_sha": "commit-juniper",
    }


@pytest.fixture
def gitlab_request(monkeypatch):
    from api.server import app

    signing_key = os.urandom(32).hex()
    monkeypatch.setenv("WEBHOOK_SECRET", signing_key)

    def post(payload, event="Merge Request Hook", org_id="tenant-ash", static_token=False):
        body = json.dumps(payload).encode()
        headers = {"X-Org-ID": org_id}
        if event is not None:
            headers["X-Gitlab-Event"] = event
        if static_token:
            headers["X-Gitlab-Token"] = signing_key
        else:
            headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(
                signing_key.encode(), body, hashlib.sha256
            ).hexdigest()
        return TestClient(app).post("/webhook/gitlab", content=body, headers=headers)

    return post


@pytest.fixture
def gitlab_payload():
    return {
        "object_kind": "merge_request",
        "project": {"id": 482, "path_with_namespace": "group-oak/repository-pine"},
        "user": {"username": "reviewer"},
        "object_attributes": {
            "iid": 953,
            "action": "open",
            "state": "opened",
            "title": "Review the merge request",
            "source_branch": "feature",
            "target_branch": "main",
            "last_commit": {"id": "commit-willow"},
        },
    }


class TestGitlabReviewTriggers:
    @pytest.mark.parametrize("action", ["update", "approved", "close", "merge", ""])
    def test_ignores_actions_without_new_review_work(
        self, gitlab_request, gitlab_payload, action
    ):
        gitlab_payload["object_attributes"]["action"] = action
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            response = gitlab_request(gitlab_payload)
            assert response.status_code == 200
            assert response.json()["status"] == "ignored"
            assert enqueue.call_count == 0

            gitlab_payload["object_attributes"]["action"] = "open"
            positive = gitlab_request(gitlab_payload)
            assert positive.status_code == 200
            assert positive.json()["status"] == "queued"
            assert enqueue.call_count == 1

    @pytest.mark.parametrize("action", ["open", "reopen", "update"])
    @pytest.mark.parametrize("event", ["Merge Request Hook", None])
    def test_ready_actions_record_head_and_preserve_draft_guards(
        self, gitlab_request, gitlab_payload, action, event
    ):
        attrs = gitlab_payload["object_attributes"]
        attrs["action"] = action
        if action == "update":
            attrs["oldrev"] = "commit-previous"
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            for field in ("draft", "work_in_progress"):
                draft = deepcopy(gitlab_payload)
                draft["object_attributes"][field] = True
                response = gitlab_request(draft, event)
                assert response.status_code == 200
                assert response.json()["status"] == "ignored"
                assert enqueue.call_count == 0

            response = gitlab_request(gitlab_payload, event)
            assert response.status_code == 200
            assert response.json() == {
                "status": "queued",
                "type": "code_review",
                "incident_id": "INC-review",
            }
            assert enqueue.call_count == 1
            context = enqueue.call_args.args[0]
            assert context.get("head_sha") == "commit-willow"
            assert context["type"] == "code_review"
            assert context["scm_platform"] == "gitlab"
            assert context["repo"] == "482"
            assert context["change_id"] == "953"

    @pytest.mark.parametrize("state", ["pending", "processing", "completed", "failed"])
    def test_duplicate_head_returns_original_response_across_states(
        self, gitlab_request, gitlab_payload, review_queue, state
    ):
        first = gitlab_request(gitlab_payload)
        assert first.status_code == 200
        incident_id = first.json()["incident_id"]
        if state != "pending":
            assert review_queue.claim_next("tenant-ash")["incident_id"] == incident_id
        if state == "completed":
            review_queue.mark_completed("tenant-ash", incident_id, {})
        elif state == "failed":
            review_queue.mark_failed("tenant-ash", incident_id, "review unavailable")
        gitlab_payload["object_attributes"].update(
            action="update", oldrev="commit-before", title="Edited title"
        )
        repeat = gitlab_request(gitlab_payload)
        assert repeat.status_code == 200
        assert repeat.json() == {
            "status": "queued",
            "type": "code_review",
            "incident_id": incident_id,
        }
        keys = review_queue.storage.list_keys("tenant-ash/queue/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["status"] == state
        assert entry["context"].get("head_sha") == "commit-willow"

    @pytest.mark.parametrize("field", ["org_id", "head_sha", "repo", "change_id"])
    def test_distinct_identity_creates_new_review(
        self, gitlab_request, gitlab_payload, review_queue, field
    ):
        first = gitlab_request(gitlab_payload)
        repeat = gitlab_request(gitlab_payload)
        assert first.status_code == repeat.status_code == 200
        assert repeat.json() == first.json()
        gitlab_payload["object_attributes"].update(action="update", oldrev="commit-before")
        org_id = "tenant-ash"
        if field == "org_id":
            org_id = "tenant-elm"
        elif field == "head_sha":
            gitlab_payload["object_attributes"]["last_commit"]["id"] = "commit-poplar"
        elif field == "repo":
            gitlab_payload["project"]["id"] = 674
        else:
            gitlab_payload["object_attributes"]["iid"] = 816
        second = gitlab_request(gitlab_payload, org_id=org_id)
        second_repeat = gitlab_request(gitlab_payload, org_id=org_id)
        assert second.status_code == second_repeat.status_code == 200
        assert second.json() == second_repeat.json()
        assert second.json()["incident_id"] != first.json()["incident_id"]
        keys = [key for key in review_queue.storage.list_keys("") if "/queue/" in key]
        assert len(keys) == 2
        assert {review_queue.storage.get_json(key)["org_id"] for key in keys} == {
            "tenant-ash",
            org_id,
        }

    @pytest.mark.parametrize("delimiter", [":", '\",\"'])
    def test_identity_field_boundaries_do_not_collide(
        self, gitlab_request, gitlab_payload, review_queue, delimiter
    ):
        del gitlab_payload["project"]["id"]
        gitlab_payload["project"]["path_with_namespace"] = f"group-oak{delimiter}842"
        first = gitlab_request(gitlab_payload)
        repeat = gitlab_request(gitlab_payload)
        assert first.status_code == repeat.status_code == 200
        assert repeat.json() == first.json()
        # Moving a delimiter across adjacent fields must form a different identity.
        gitlab_payload["project"]["path_with_namespace"] = "group-oak"
        gitlab_payload["object_attributes"]["iid"] = f"842{delimiter}953"
        second = gitlab_request(gitlab_payload)
        second_repeat = gitlab_request(gitlab_payload)
        assert second.status_code == second_repeat.status_code == 200
        assert second_repeat.json() == second.json()
        assert second.json()["incident_id"] != first.json()["incident_id"]
        assert len(review_queue.storage.list_keys("tenant-ash/queue/")) == 2

    @pytest.mark.parametrize("committed", [False, True])
    def test_write_error_succeeds_only_when_record_persisted(
        self, monkeypatch, gitlab_request, gitlab_payload, review_queue, committed
    ):
        storage = review_queue.storage
        put = storage.put_json_if_absent

        def lose_acknowledgement(key, data):
            if committed:
                put(key, data)
            raise RuntimeError("Review write unavailable")

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", lose_acknowledgement)
            if committed:
                response = gitlab_request(gitlab_payload)
                assert response.status_code == 200
                keys = storage.list_keys("tenant-ash/queue/")
                assert len(keys) == 1
                entry = storage.get_json(keys[0])
                assert entry["context"].get("head_sha") == "commit-willow"
                assert response.json() == {
                    "status": "queued",
                    "type": "code_review",
                    "incident_id": entry["incident_id"],
                }
            else:
                failure = None
                try:
                    gitlab_request(gitlab_payload)
                except RuntimeError as error:
                    failure = error
                assert failure is not None
                assert str(failure) == "Review write unavailable"
                assert storage.list_keys("tenant-ash/queue/") == []

        retry = gitlab_request(gitlab_payload)
        assert retry.status_code == 200
        keys = storage.list_keys("tenant-ash/queue/")
        assert len(keys) == 1
        assert retry.json()["incident_id"] == storage.get_json(keys[0])["incident_id"]
        if committed:
            assert retry.json() == response.json()

    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    def test_interrupted_compaction_resumes_without_admitting_stale_claim(
        self, monkeypatch, gitlab_request, gitlab_payload, review_queue, terminal
    ):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = review_queue.storage
        first = gitlab_request(gitlab_payload)
        assert first.status_code == 200
        incident_id = first.json()["incident_id"]
        review_key = storage.list_keys("tenant-ash/queue/")[0]
        assert storage.get_json(review_key)["context"].get("head_sha") == "commit-willow"
        get, put = storage.get_json, storage.put_json
        snapshot_taken = threading.Event()
        release_snapshot = threading.Event()

        def hold_pending(key):
            entry = get(key)
            if (
                key == review_key
                and entry.get("status") == "pending"
                and not snapshot_taken.is_set()
            ):
                snapshot_taken.set()
                assert release_snapshot.wait(10)
            return entry

        monkeypatch.setattr(storage, "get_json", hold_pending)
        with ThreadPoolExecutor(max_workers=1) as executor:
            stale = executor.submit(review_queue.claim_next, "tenant-ash")
            try:
                assert snapshot_taken.wait(10)
                assert review_queue.claim_next("tenant-ash")["incident_id"] == incident_id
                if terminal == "completed":
                    review_queue.mark_completed("tenant-ash", incident_id, {})
                else:
                    review_queue.mark_failed("tenant-ash", incident_id, "review unavailable")
                ended_field = "completed_at" if terminal == "completed" else "failed_at"
                aged = get(review_key)
                aged[ended_field] = "2020-01-01T00:00:00+00:00"
                put(review_key, aged)
                claim_key = storage.list_keys("tenant-ash/review_claims/")[0]
                minimal = {
                    "incident_id": incident_id,
                    "org_id": "tenant-ash",
                    "status": terminal,
                    ended_field: "2020-01-01T00:00:00+00:00",
                }

                def interrupt_canonical_write(key, data):
                    if key == review_key:
                        assert get(claim_key) == minimal
                        raise InterruptedQueueWrite()
                    return put(key, data)

                with monkeypatch.context() as injection:
                    injection.setattr(storage, "put_json", interrupt_canonical_write)
                    with pytest.raises(InterruptedQueueWrite):
                        IncidentStore(storage).apply_retention("tenant-ash")
                assert get(claim_key) == minimal
                assert get(review_key) == aged
                repeat = gitlab_request(gitlab_payload)
                assert repeat.status_code == 200
                assert repeat.json() == first.json()
                assert IncidentStore(storage).apply_retention("tenant-ash") == 0
                assert get(review_key) == get(claim_key) == minimal
                assert IncidentStore(storage).apply_retention("tenant-ash") == 0
            finally:
                release_snapshot.set()
            assert stale.result(timeout=10) is None
        restarted = IncidentQueue(storage)
        monkeypatch.setattr("api.server.incident_queue", restarted)
        assert restarted.claim_next("tenant-ash") is None
        assert restarted.recover_stale_processing("tenant-ash") == 0
        repeat = gitlab_request(gitlab_payload)
        assert repeat.status_code == 200
        assert repeat.json() == first.json()
        assert storage.list_keys("tenant-ash/queue/") == [review_key]
        assert get(review_key) == get(claim_key) == minimal

    def test_static_token_review_and_failed_pipeline(
        self, gitlab_request, gitlab_payload, review_queue
    ):
        review = gitlab_request(gitlab_payload, static_token=True)
        assert review.status_code == 200
        keys = review_queue.storage.list_keys("tenant-ash/queue/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["context"].get("head_sha") == "commit-willow"
        pipeline = {
            "object_kind": "pipeline",
            "project": {"id": 482},
            "object_attributes": {"id": 617, "status": "failed"},
        }
        response = gitlab_request(pipeline, event=None)
        assert response.status_code == 200
        assert response.json()["status"] == "queued"
        assert response.json()["type"] == "cicd"
        keys = review_queue.storage.list_keys("tenant-ash/queue/pending/")
        assert len(keys) == 1
        assert review_queue.storage.get_json(keys[0])["context"] == {
            "type": "cicd",
            "source": "gitlab_ci",
            "org_id": "tenant-ash",
            "project_id": "482",
            "pipeline_id": 617,
            "labels": {"cicd_platform": "gitlab"},
        }


class TestBitbucketReviewTriggers:
    @pytest.mark.parametrize(
        "event",
        [
            "pullrequest:comment_created",
            "pullrequest:fulfilled",
            "pullrequest:rejected",
            None,
        ],
    )
    def test_ignores_non_review_events(self, bitbucket_request, bitbucket_payload, event):
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            response = bitbucket_request(bitbucket_payload, event)
            assert response.status_code == 200
            assert response.json()["status"] == "ignored"
            assert enqueue.call_count == 0

            response = bitbucket_request(bitbucket_payload)
            assert response.status_code == 200
            assert response.json()["status"] == "queued"
            assert enqueue.call_count == 1

    @pytest.mark.parametrize("event", ["pullrequest:created", "pullrequest:updated"])
    def test_reviews_only_ready_prs_and_records_head(
        self, bitbucket_request, bitbucket_payload, event
    ):
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            for draft in ({"draft": True}, {"state": "DRAFT"}):
                payload = dict(bitbucket_payload)
                payload["pullrequest"] = {**bitbucket_payload["pullrequest"], **draft}
                response = bitbucket_request(payload, event)
                assert response.status_code == 200
                assert response.json()["status"] == "ignored"
                assert enqueue.call_count == 0

            response = bitbucket_request(bitbucket_payload, event)
            assert response.status_code == 200
            assert response.json()["status"] == "queued"
            assert response.json()["type"] == "code_review"
            assert enqueue.call_count == 1
            context = enqueue.call_args.args[0]
            assert context.get("head_sha") == "commit-juniper"
            assert context["type"] == "code_review"

    @pytest.mark.parametrize("state", ["pending", "processing", "completed", "failed"])
    def test_duplicate_head_across_queue_states(
        self, bitbucket_request, bitbucket_payload, review_queue, state
    ):
        first = bitbucket_request(bitbucket_payload)
        assert first.status_code == 200
        assert first.json()["status"] == "queued"
        incident_id = first.json()["incident_id"]
        if state != "pending":
            entry = review_queue.claim_next("tenant-ember")
            assert entry["incident_id"] == incident_id
        if state == "completed":
            review_queue.mark_completed("tenant-ember", incident_id, {})
        elif state == "failed":
            review_queue.mark_failed("tenant-ember", incident_id, "review unavailable")

        bitbucket_payload["pullrequest"]["title"] = "Edited review title"
        repeat = bitbucket_request(bitbucket_payload, "pullrequest:updated")
        assert repeat.status_code == 200
        keys = review_queue.storage.list_keys("tenant-ember/queue/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["status"] == state
        assert entry["context"].get("head_sha") == "commit-juniper"

    @pytest.mark.parametrize("field", ["org_id", "repo", "change_id", "head_sha"])
    def test_distinct_review_identity_enqueues_separately(
        self, bitbucket_request, bitbucket_payload, review_queue, field
    ):
        first = bitbucket_request(bitbucket_payload)
        bitbucket_request(bitbucket_payload)
        assert len(review_queue.storage.list_keys("tenant-ember/queue/")) == 1

        org_id = "tenant-ember"
        if field == "org_id":
            org_id = "tenant-birch"
        elif field == "repo":
            bitbucket_payload["repository"]["slug"] = "repository-willow"
        elif field == "change_id":
            bitbucket_payload["pullrequest"]["id"] = 845
        else:
            bitbucket_payload["pullrequest"]["source"]["commit"]["hash"] = "commit-spruce"
        second = bitbucket_request(bitbucket_payload, "pullrequest:updated", org_id)
        assert first.status_code == second.status_code == 200
        assert second.json()["status"] == "queued"
        assert first.json()["incident_id"] != second.json()["incident_id"]
        bitbucket_request(bitbucket_payload, "pullrequest:updated", org_id)
        keys = [key for key in review_queue.storage.list_keys("") if "/queue/" in key]
        assert len(keys) == 2
        assert {review_queue.storage.get_json(key)["org_id"] for key in keys} == {
            "tenant-ember",
            org_id,
        }

    def test_concurrent_duplicate_deliveries_enqueue_once(
        self, bitbucket_request, bitbucket_payload, review_queue
    ):
        with ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(
                executor.map(lambda _: bitbucket_request(bitbucket_payload), range(8))
            )
        assert all(response.status_code == 200 for response in responses)
        assert len(review_queue.storage.list_keys("tenant-ember/queue/")) == 1

    def test_shared_dedupe_includes_provider(self, review_queue):
        context = {
            "type": "code_review",
            "scm_platform": "bitbucket",
            "repo": "workspace-cedar/repository-maple",
            "change_id": "731",
            "head_sha": "commit-juniper",
        }
        first = review_queue.enqueue("tenant-ember", context)
        review_queue.enqueue("tenant-ember", context)
        assert len(review_queue.storage.list_keys("tenant-ember/queue/")) == 1
        second = review_queue.enqueue("tenant-ember", {**context, "scm_platform": "gitlab"})
        assert first != second
        assert len(review_queue.storage.list_keys("tenant-ember/queue/")) == 2

    @pytest.mark.parametrize("window", ["before_pending", "after_pending"])
    def test_interrupted_review_write_recovers_real_work(
        self,
        monkeypatch,
        bitbucket_request,
        bitbucket_payload,
        review_queue,
        review_context,
        window,
    ):
        storage = review_queue.storage
        put = storage.put_json
        put_if_absent = storage.put_json_if_absent

        def interrupt(key, data, write):
            if "/queue/" not in key:
                return write(key, data)
            if window == "before_pending":
                raise InterruptedQueueWrite()
            write(key, data)
            raise RuntimeError("Queue write acknowledgement lost")

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json", lambda key, data: interrupt(key, data, put))
            injection.setattr(
                storage,
                "put_json_if_absent",
                lambda key, data: interrupt(key, data, put_if_absent),
            )
            if window == "before_pending":
                with pytest.raises(InterruptedQueueWrite):
                    review_queue.enqueue("tenant-ember", review_context)
            else:
                try:
                    review_queue.enqueue("tenant-ember", review_context)
                except RuntimeError:
                    # A lost acknowledgement may surface even though data committed.
                    pass

        restarted = IncidentQueue(storage)
        monkeypatch.setattr("api.server.incident_queue", restarted)
        response = bitbucket_request(bitbucket_payload)
        repeat = bitbucket_request(bitbucket_payload)
        assert response.status_code == repeat.status_code == 200
        keys = storage.list_keys("tenant-ember/queue/")
        assert len(keys) == 1
        entry = storage.get_json(keys[0])
        assert entry["status"] == "pending"
        assert (
            entry["incident_id"]
            == response.json()["incident_id"]
            == repeat.json()["incident_id"]
        )
        monkeypatch.setenv("ORG_ID", "tenant-configured")
        monkeypatch.delenv("ORG_IDS", raising=False)
        assert "tenant-ember" in restarted.list_pending_org_ids()

        with ThreadPoolExecutor(max_workers=8) as executor:
            claimed = list(
                executor.map(lambda _: restarted.claim_next("tenant-ember"), range(8))
            )
        assert len([item for item in claimed if item is not None]) == 1
        assert restarted.recover_stale_processing("tenant-ember") == 1
        recovered = restarted.claim_next("tenant-ember")
        assert recovered["incident_id"] == entry["incident_id"]
        assert recovered["attempts"] == 2
        restarted.mark_completed("tenant-ember", entry["incident_id"], {})
        assert restarted.claim_next("tenant-ember") is None
        assert "tenant-ember" not in restarted.list_pending_org_ids()

        # Review history remains the dedupe record after ordinary queue retention.
        expired = storage.get_json(keys[0])
        expired["completed_at"] = "2020-01-01T00:00:00+00:00"
        put(keys[0], expired)
        ordinary_key = storage.queue_key("tenant-ember", "completed", "INC-expired")
        put(ordinary_key, {"completed_at": "2020-01-01T00:00:00+00:00"})
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        assert IncidentStore(storage).apply_retention("tenant-ember") == 1
        assert not storage.exists(ordinary_key)
        repeat = bitbucket_request(bitbucket_payload)
        assert repeat.status_code == 200
        assert repeat.json()["incident_id"] == entry["incident_id"]
        assert len(storage.list_keys("tenant-ember/queue/")) == 1

        # Recover a worker stop on either side of the review's status update.
        for persist_status in (False, True):
            context = {**review_context, "head_sha": f"commit-claim-{persist_status}"}
            incident_id = restarted.enqueue("tenant-ember", context)

            def interrupt_status(key, data):
                if data.get("status") == "processing":
                    if persist_status:
                        put(key, data)
                    raise InterruptedQueueWrite()
                return put(key, data)

            with monkeypatch.context() as injection:
                injection.setattr(storage, "put_json", interrupt_status)
                with pytest.raises(InterruptedQueueWrite):
                    restarted.claim_next("tenant-ember")
            assert restarted.recover_stale_processing("tenant-ember") == 1
            recovered = restarted.claim_next("tenant-ember")
            assert recovered["incident_id"] == incident_id
            assert recovered["attempts"] == 2
            restarted.mark_failed("tenant-ember", incident_id, "review unavailable")
            assert restarted.claim_next("tenant-ember") is None

        # Incomplete and non-review contexts keep independent queue entries.
        contexts = [
            {key: value for key, value in review_context.items() if key != "type"}
        ]
        contexts.append({**review_context, "type": "server"})
        for field in ("scm_platform", "repo", "change_id", "head_sha"):
            contexts.append(
                {key: value for key, value in review_context.items() if key != field}
            )
            contexts.append({**review_context, field: ""})
        for index, context in enumerate(contexts):
            first = restarted.enqueue("tenant-alder", context)
            second = restarted.enqueue("tenant-alder", context)
            assert first != second
            assert len(storage.list_keys("tenant-alder/queue/pending/")) == (
                index + 1
            ) * 2

    @pytest.mark.parametrize("acknowledge", ["before_rollback", "after_rollback"])
    def test_concurrent_duplicates_survive_owner_write_failure(
        self,
        monkeypatch,
        bitbucket_request,
        bitbucket_payload,
        review_queue,
        acknowledge,
    ):
        storage = review_queue.storage
        put = storage.put_json
        put_if_absent = storage.put_json_if_absent
        owner_waiting = threading.Event()
        release_owner = threading.Event()
        owner_finished = threading.Event()
        duplicates_ready = threading.Barrier(8)
        first_lock = threading.Lock()
        first_write = True

        def pending_write(key, data, write):
            nonlocal first_write
            with first_lock:
                owner = first_write and "/queue/" in key
                if owner:
                    first_write = False
            if owner:
                owner_waiting.set()
                assert release_owner.wait(10)
                raise RuntimeError("Queue write failed before persistence")
            return write(key, data)

        def conditional_write(key, data):
            result = pending_write(key, data, put_if_absent)
            if owner_waiting.is_set():
                duplicates_ready.wait(timeout=10)
                if acknowledge == "after_rollback":
                    assert owner_finished.wait(10)
            return result

        monkeypatch.setattr(storage, "put_json", lambda key, data: pending_write(key, data, put))
        monkeypatch.setattr(storage, "put_json_if_absent", conditional_write)

        def post_owner():
            try:
                return bitbucket_request(bitbucket_payload, raise_server_exceptions=False)
            finally:
                owner_finished.set()

        with ThreadPoolExecutor(max_workers=8) as executor:
            owner = executor.submit(post_owner)
            try:
                assert owner_waiting.wait(10)
                duplicates = [
                    executor.submit(
                        bitbucket_request,
                        bitbucket_payload,
                        "pullrequest:created",
                        "tenant-ember",
                        False,
                    )
                    for _ in range(7)
                ]
                duplicates_ready.wait(timeout=10)
                if acknowledge == "before_rollback":
                    responses = [future.result(timeout=10) for future in duplicates]
            finally:
                release_owner.set()
            owner_response = owner.result(timeout=10)
            assert owner_response.status_code == 200
            if acknowledge == "after_rollback":
                responses = [future.result(timeout=10) for future in duplicates]

        responses.append(owner_response)
        assert all(response.status_code == 200 for response in responses)
        keys = storage.list_keys("tenant-ember/queue/")
        assert len(keys) == 1
        entry = storage.get_json(keys[0])
        assert entry["status"] == "pending"
        assert {response.json()["incident_id"] for response in responses} == {
            entry["incident_id"]
        }
        monkeypatch.setattr(storage, "put_json", put)
        monkeypatch.setattr(storage, "put_json_if_absent", put_if_absent)
        repeat = bitbucket_request(bitbucket_payload)
        assert repeat.status_code == 200
        assert repeat.json()["incident_id"] == entry["incident_id"]
        assert len(storage.list_keys("tenant-ember/queue/")) == 1

    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    @pytest.mark.parametrize("held", ["pending_claim", "processing_recovery"])
    def test_terminal_retention_compacts_payloads_and_preserves_fences(
        self,
        monkeypatch,
        bitbucket_request,
        bitbucket_payload,
        review_queue,
        review_context,
        terminal,
        held,
    ):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = review_queue.storage
        response = bitbucket_request(bitbucket_payload)
        assert response.status_code == 200
        incident_id = response.json()["incident_id"]
        review_key = storage.list_keys("tenant-ember/queue/")[0]
        if held == "processing_recovery":
            assert review_queue.claim_next("tenant-ember")["incident_id"] == incident_id

        get = storage.get_json
        snapshot_taken = threading.Event()
        release_snapshot = threading.Event()
        expected_status = "pending" if held == "pending_claim" else "processing"

        def hold_snapshot(key):
            entry = get(key)
            if (
                key == review_key
                and entry.get("status") == expected_status
                and not snapshot_taken.is_set()
            ):
                snapshot_taken.set()
                assert release_snapshot.wait(10)
            return entry

        monkeypatch.setattr(storage, "get_json", hold_snapshot)
        with ThreadPoolExecutor(max_workers=1) as executor:
            action = (
                review_queue.claim_next
                if held == "pending_claim"
                else review_queue.recover_stale_processing
            )
            stale = executor.submit(action, "tenant-ember")
            try:
                assert snapshot_taken.wait(10)
                if held == "pending_claim":
                    assert review_queue.claim_next("tenant-ember")["incident_id"] == incident_id
                if terminal == "completed":
                    review_queue.mark_completed("tenant-ember", incident_id, {"resolved": True})
                else:
                    review_queue.mark_failed("tenant-ember", incident_id, "review unavailable")
                claim_key = storage.list_keys("tenant-ember/review_claims/")[0]
                store = IncidentStore(storage)
                assert store.apply_retention("tenant-ember") == 0
                assert get(review_key)["context"]["head_sha"] == "commit-juniper"
                assert get(claim_key)["context"]["head_sha"] == "commit-juniper"

                ended_field = "completed_at" if terminal == "completed" else "failed_at"
                aged = get(review_key)
                fresh_timestamp = aged[ended_field]
                aged[ended_field] = "2020-01-01T00:00:00+00:00"
                storage.put_json(review_key, aged)
                expired_key = storage.queue_key("tenant-ember", "completed", "INC-expired")
                fresh_key = storage.queue_key("tenant-ember", "completed", "INC-fresh")
                storage.put_json(expired_key, {"completed_at": aged[ended_field]})
                fresh = {"completed_at": fresh_timestamp, "context": {"type": "server"}}
                storage.put_json(fresh_key, fresh)

                assert store.apply_retention("tenant-ember") == 1
                assert not storage.exists(expired_key)
                assert get(fresh_key) == fresh
                assert "context" not in get(review_key)
                assert "context" not in get(claim_key)
                expected = {
                    "incident_id": incident_id,
                    "org_id": "tenant-ember",
                    "status": terminal,
                    ended_field: "2020-01-01T00:00:00+00:00",
                }
                assert get(review_key) == expected
                assert get(claim_key) == expected
                assert store.apply_retention("tenant-ember") == 0
            finally:
                release_snapshot.set()
            assert stale.result(timeout=10) == (None if held == "pending_claim" else 0)

        restarted = IncidentQueue(storage)
        monkeypatch.setattr("api.server.incident_queue", restarted)
        for _ in range(2):
            repeat = bitbucket_request(bitbucket_payload, "pullrequest:updated")
            assert repeat.status_code == 200
            assert repeat.json()["incident_id"] == incident_id
            assert get(review_key) == expected
        assert restarted.claim_next("tenant-ember") is None
        assert restarted.recover_stale_processing("tenant-ember") == 0
        assert get(claim_key) == expected
        assert storage.list_keys("tenant-ember/queue/reviews/") == [review_key]

        live_context = {**review_context, "head_sha": "commit-live-processing"}
        processing_id = restarted.enqueue("tenant-ember", live_context)
        assert restarted.claim_next("tenant-ember")["incident_id"] == processing_id
        pending_id = restarted.enqueue(
            "tenant-ember", {**review_context, "head_sha": "commit-live-pending"}
        )
        live_keys = [
            key
            for key in storage.list_keys("tenant-ember/queue/reviews/")
            if key != review_key
        ] + [
            key
            for key in storage.list_keys("tenant-ember/review_claims/")
            if key != claim_key
        ]
        for key in live_keys:
            entry = get(key)
            entry["created_at"] = "2020-01-01T00:00:00+00:00"
            if "claimed_at" in entry:
                entry["claimed_at"] = "2020-01-01T00:00:00+00:00"
            storage.put_json(key, entry)
        before_retention = {key: get(key) for key in live_keys}
        assert store.apply_retention("tenant-ember") == 0
        assert {key: get(key) for key in live_keys} == before_retention
        assert all("context" in get(key) for key in live_keys)
        assert restarted.recover_stale_processing("tenant-ember") == 1
        claimed = [restarted.claim_next("tenant-ember") for _ in range(2)]
        assert {entry["incident_id"] for entry in claimed} == {processing_id, pending_id}
        recovered = next(
            entry for entry in claimed if entry["incident_id"] == processing_id
        )
        assert recovered["context"] == live_context
        assert recovered["attempts"] == 2
