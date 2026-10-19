"""Retained host approvals expire, execute once, and bound retained state."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import itertools
import json
import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest
from botocore.exceptions import ClientError, ParamValidationError

from services import approval_store
from services.approval_store import CommandApprovalStore
from storage.azure_storage import AzureBlobStorage
from storage.base import StorageProvider
from storage.gcs_storage import GCSStorage
from storage.memory_storage import MemoryStorage
from storage.s3_storage import S3Storage
from tests.test_host_mutation_approval import agent, approval_executor


@pytest.fixture
def clock(monkeypatch):
    now = [1_800_000_000.0]
    monkeypatch.setattr(
        approval_store, "time", SimpleNamespace(time=lambda: now[0]), raising=False
    )
    return now


class ConditionalConflict(Exception):
    pass


@pytest.fixture(params=["memory", "s3", "minio", "gcs", "azure"])
def backend(request, monkeypatch):
    """Real backend methods; only cloud SDK transports use an in-memory server."""
    objects = MemoryStorage()
    if request.param == "memory":
        return objects, objects

    versions = {}
    generation = itertools.count(1)

    def snapshot(key):
        with objects._lock:
            return objects._objects.get(key), versions.get(key)

    def create(key, body, conditional, expected=None):
        hook = getattr(objects, "before_conditional_write", None)
        if expected is not None and hook is not None:
            objects.before_conditional_write = None
            hook(key)
        with objects._lock:
            if conditional and key in objects._objects:
                raise ConditionalConflict()
            if expected is not None and versions.get(key) != expected:
                raise ConditionalConflict()
            objects._objects[key] = body if isinstance(body, bytes) else body.encode()
            versions[key] = next(generation)

    def remove(key):
        with objects._lock:
            objects._objects.pop(key, None)
            versions.pop(key, None)

    if request.param in {"s3", "minio"}:

        class S3Client:
            exceptions = SimpleNamespace(NoSuchKey=ConditionalConflict)

            def put_object(self, *, Bucket, Key, Body, ContentType, **kwargs):
                assert set(kwargs) <= {"IfNoneMatch", "IfMatch"}
                try:
                    create(
                        Key,
                        Body,
                        kwargs.get("IfNoneMatch") == "*",
                        (
                            int(kwargs["IfMatch"])
                            if kwargs.get("IfMatch", "").isdigit()
                            else (-1 if "IfMatch" in kwargs else None)
                        ),
                    )
                except ConditionalConflict:
                    raise ClientError(
                        {"Error": {"Code": "PreconditionFailed"}}, "PutObject"
                    ) from None

            def get_object(self, *, Bucket, Key):
                body, version = snapshot(Key)
                if body is None:
                    raise ConditionalConflict()
                return {"Body": io.BytesIO(body), "ETag": str(version)}

            def head_object(self, *, Bucket, Key):
                if not objects.exists(Key):
                    raise ConditionalConflict()

            def delete_object(self, *, Bucket, Key):
                remove(Key)

            def get_paginator(self, operation):
                assert operation == "list_objects_v2"
                return SimpleNamespace(
                    paginate=lambda **kw: [
                        {
                            "Contents": [
                                {"Key": key} for key in objects.list_keys(kw["Prefix"])
                            ]
                        }
                    ]
                )

        storage = S3Storage.__new__(S3Storage)
        storage.bucket = "approval-fixture"
        storage._client = S3Client()
        return storage, objects

    # The optional SDKs are not dependencies of these tests. Model their named
    # conflict exception while exercising the real storage adapter methods.
    module_name = (
        "google.api_core.exceptions"
        if request.param == "gcs"
        else "azure.core.exceptions"
    )
    for package in [module_name.split(".")[0], ".".join(module_name.split(".")[:2])]:
        if package not in sys.modules:
            module = ModuleType(package)
            module.__path__ = []
            monkeypatch.setitem(sys.modules, package, module)
    module = ModuleType(module_name)
    module.PreconditionFailed = ConditionalConflict
    module.NotFound = ConditionalConflict
    module.ResourceExistsError = ConditionalConflict
    module.ResourceNotFoundError = ConditionalConflict
    module.ResourceModifiedError = ConditionalConflict
    monkeypatch.setitem(sys.modules, module_name, module)
    if request.param == "azure":
        monkeypatch.setattr(
            sys.modules["azure.core"],
            "MatchConditions",
            SimpleNamespace(IfNotModified="if-not-modified"),
            raising=False,
        )

    class Blob:
        def __init__(self, key):
            self.key = key

        def exists(self):
            return objects.exists(self.key)

        def upload_from_string(self, body, content_type, **kwargs):
            assert set(kwargs) <= {"if_generation_match"}
            version = kwargs.get("if_generation_match")
            create(self.key, body, version == 0, version if version else None)

        def upload_blob(self, body, overwrite, content_type=None, **kwargs):
            assert set(kwargs) <= {"etag", "match_condition"}
            if "etag" in kwargs:
                assert kwargs["match_condition"] == "if-not-modified"
            create(
                self.key,
                body,
                not overwrite,
                int(kwargs["etag"]) if "etag" in kwargs else None,
            )

        def reload(self):
            body, version = snapshot(self.key)
            if body is None:
                raise ConditionalConflict()
            self.generation = version

        def download_as_bytes(self, **kwargs):
            body, version = snapshot(self.key)
            assert set(kwargs) <= {"if_generation_match"}
            if body is None or kwargs.get("if_generation_match", version) != version:
                raise ConditionalConflict()
            return body

        def get_blob_properties(self):
            body, version = snapshot(self.key)
            if body is None:
                raise ConditionalConflict()
            return SimpleNamespace(etag=str(version))

        def download_blob(self, **kwargs):
            body, version = snapshot(self.key)
            assert set(kwargs) <= {"etag", "match_condition"}
            if body is None or kwargs.get("etag", str(version)) != str(version):
                raise ConditionalConflict()
            if "etag" in kwargs:
                assert kwargs["match_condition"] == "if-not-modified"
            return SimpleNamespace(readall=lambda: body)

        def delete(self):
            remove(self.key)

        delete_blob = delete

    if request.param == "gcs":
        storage = GCSStorage.__new__(GCSStorage)
        storage.bucket_name = "approval-fixture"
        storage._bucket = SimpleNamespace(blob=Blob)
        storage._client = SimpleNamespace(
            list_blobs=lambda bucket, prefix: [
                SimpleNamespace(name=key) for key in objects.list_keys(prefix)
            ]
        )
    else:
        storage = AzureBlobStorage.__new__(AzureBlobStorage)
        storage._container_client = SimpleNamespace(
            get_blob_client=Blob,
            list_blobs=lambda name_starts_with: [
                SimpleNamespace(name=key) for key in objects.list_keys(name_starts_with)
            ],
        )
    return storage, objects


def retained_bytes(objects):
    return b"".join(objects.get_bytes(key) for key in objects.list_keys(""))


@pytest.mark.asyncio
@pytest.mark.parametrize("age", [3600, 3601])
async def test_expired_agent_approval_fails_closed(
    agent, approval_executor, clock, age
):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.31"})
    assert runner.calls == []
    clock[0] += age

    result = await approval_executor.run(approval["command"])

    assert result.get("blocked") is True, result
    assert result.get("success") is False
    assert result.get("returncode") == 1
    assert runner.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_reference_is_spent_after_one_execution(
    agent, approval_executor, clock, fail
):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.32"})
    assert runner.calls == []
    runner.forbid_all = False
    runner.allow_mutations = True
    runner.fail_prefix = "nginx -t" if fail else None
    first = await approval_executor.run(approval["command"])
    assert first["success"] is not fail
    first_calls = list(runner.calls)

    second = await approval_executor.run(approval["command"])

    assert second.get("blocked") is True, second
    assert second.get("success") is False
    assert second.get("returncode") == 1
    assert runner.calls == first_calls


def test_concurrent_resolvers_atomically_choose_one_winner(backend, clock, monkeypatch):
    storage, objects = backend
    reference = CommandApprovalStore(storage).retain(
        "retained-command", host="203.0.113.33"
    )
    barrier = threading.Barrier(8)
    original = storage.get_json

    def read_together(key):
        record = original(key)
        if isinstance(record, dict) and "command" in record:
            barrier.wait(timeout=10)
        return record

    monkeypatch.setattr(storage, "get_json", read_together)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: CommandApprovalStore(storage).resolve(reference), range(8)
            )
        )

    assert results.count("retained-command") == 1, results
    assert results.count(None) == 7
    assert b"retained-command" not in retained_bytes(objects)


def test_contender_paused_past_expiry_cannot_execute(clock, monkeypatch):
    storage = MemoryStorage()
    store = CommandApprovalStore(storage)
    reference = store.retain("late-command")
    clock[0] += 3599
    original = storage.get_json

    def pause_before_claim(key):
        record = original(key)
        if isinstance(record, dict) and "command" in record:
            clock[0] += 2
        return record

    monkeypatch.setattr(storage, "get_json", pause_before_claim)
    assert store.resolve(reference) is None
    assert b"late-command" not in retained_bytes(storage)


@pytest.mark.asyncio
async def test_concurrent_executor_replay_blocks_every_loser(agent, clock, monkeypatch):
    instance, runner = agent
    runner.forbid_all = True
    approval = await instance.execute_tool("restart_nginx", {"host": "203.0.113.34"})
    assert runner.calls == []
    from tools.executor import SafeExecutor

    executor = SafeExecutor()
    executed = []

    async def execute(command, host=None):
        executed.append(command)
        await asyncio.sleep(0)
        return {"success": True, "returncode": 0}

    monkeypatch.setattr(executor, "_exec", execute)
    results = await asyncio.gather(
        *(executor.run(approval["command"]) for _ in range(8))
    )
    assert len(executed) == 1
    assert sum(result.get("blocked") is True for result in results) == 7
    assert sum(result.get("success") is True for result in results) == 1


def test_completed_configurations_are_reclaimed(backend, clock):
    storage, objects = backend
    for _ in range(4):
        store = CommandApprovalStore(storage)
        command = "configuration-marker:" + "x" * (32 * 1024)
        reference = store.retain(command)
        assert store.resolve(reference) == command
    data = retained_bytes(objects)
    assert b"configuration-marker" not in data
    assert len(data) < 4096


def test_abandoned_records_expire_and_are_swept_on_later_access(backend, clock):
    storage, objects = backend
    reference = CommandApprovalStore(storage).retain("abandoned-configuration")
    clock[0] += 3601
    store = CommandApprovalStore(storage)
    store.retain("new-operation")

    assert store.resolve(reference) is None
    assert b"abandoned-configuration" not in retained_bytes(objects)


def test_admission_is_bounded_and_recovers_in_the_next_window(
    backend, clock, monkeypatch
):
    storage, objects = backend
    monkeypatch.setattr(approval_store, "APPROVALS_PER_WINDOW", 2, raising=False)
    store = CommandApprovalStore(storage)
    refs = [store.retain("pending-configuration") for _ in range(2)]
    with pytest.raises(RuntimeError, match="capacity"):
        store.retain("excess-operation")
    assert len(objects.list_keys("")) <= 6
    clock[0] += 7201
    new_ref = store.retain("new-window-operation")
    assert all(store.resolve(reference) is None for reference in refs)
    assert store.resolve(new_ref) == "new-window-operation"
    assert b"pending-configuration" not in retained_bytes(objects)
    assert len(objects.list_keys("")) <= 3


def test_concurrent_admission_cannot_exceed_capacity(backend, clock, monkeypatch):
    storage, objects = backend
    monkeypatch.setattr(approval_store, "APPROVALS_PER_WINDOW", 2, raising=False)
    barrier = threading.Barrier(8)

    def retain(_):
        barrier.wait(timeout=10)
        try:
            return CommandApprovalStore(storage).retain("pending-operation")
        except RuntimeError as exc:
            assert "capacity" in str(exc)
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(retain, range(8)))
    assert sum(reference is not None for reference in results) == 2
    assert len(objects.list_keys("")) <= 6


def test_completed_claim_markers_are_reclaimed_after_expiry(backend, clock):
    storage, objects = backend
    store = CommandApprovalStore(storage)
    reference = store.retain("completed-operation")
    assert store.resolve(reference) == "completed-operation"
    clock[0] += 7201
    store.resolve(reference)
    assert objects.list_keys("") == []


def test_oversized_records_are_rejected_without_retaining_payload(
    backend, clock, monkeypatch
):
    storage, objects = backend
    monkeypatch.setattr(
        approval_store, "MAX_APPROVAL_RECORD_BYTES", 1024, raising=False
    )
    with pytest.raises(ValueError, match="size"):
        CommandApprovalStore(storage).retain("x" * 2048)
    assert objects.list_keys("") == []


def test_legacy_records_without_expiry_are_rejected_and_reclaimed(clock):
    storage = MemoryStorage()
    reference = "agent-approval:" + "1" * 32 + " (localhost)"
    storage.put_json(
        "default/approvals/" + "1" * 32 + ".json",
        {
            "org_id": "default",
            "reference": reference,
            "command": "legacy-operation",
            "host": None,
        },
    )
    assert CommandApprovalStore(storage).resolve(reference) is None
    assert storage.list_keys("default/approvals/") == []


def test_non_atomic_storage_fallback_is_refused(clock):
    class UnsafeStorage(MemoryStorage):
        put_json_if_absent = StorageProvider.put_json_if_absent

    with pytest.raises(RuntimeError, match="atomic"):
        CommandApprovalStore(UnsafeStorage()).retain("must-not-be-approved")


def test_s3_sdk_without_conditions_is_refused_instead_of_using_fallback(clock):
    storage = S3Storage.__new__(S3Storage)
    storage.bucket = "approval-fixture"

    def unsupported(**kwargs):
        raise ParamValidationError(report="conditional writes unavailable")

    storage._client = SimpleNamespace(
        put_object=unsupported,
        head_object=lambda **kw: None,
        get_paginator=lambda operation: SimpleNamespace(paginate=lambda **kw: []),
    )
    with pytest.raises(RuntimeError, match="atomic"):
        CommandApprovalStore(storage).retain("must-not-be-approved")


@pytest.mark.parametrize(
    "reclaim", [False, True], ids=["before-cleanup-control", "after-cleanup"]
)
@pytest.mark.parametrize("clock_mode", ["offset", "step-back"])
def test_stale_reader_cannot_execute_after_terminal_state_reclamation(
    backend, monkeypatch, reclaim, clock_mode
):
    """Two execution boundaries from one reference are forbidden, across clocks."""
    storage, _ = backend
    from tools.executor import SafeExecutor

    worker = threading.local()
    start = 1_800_000_000.0
    worker.now = start
    monkeypatch.setattr(
        approval_store, "time", SimpleNamespace(time=lambda: worker.now)
    )
    monkeypatch.setattr("storage.factory.get_storage", lambda: storage)
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    reference = CommandApprovalStore(storage).retain("exact-retained-operation")
    reader_has_payload = threading.Event()
    resume_reader = threading.Event()
    original_read = storage.get_json

    def pause_cached_reader(key):
        record = original_read(key)
        if (
            getattr(worker, "reader", False)
            and isinstance(record, dict)
            and "command" in record
        ):
            reader_has_payload.set()
            assert resume_reader.wait(timeout=10)
            if clock_mode == "step-back":
                worker.now = start + 3590
        return record

    monkeypatch.setattr(storage, "get_json", pause_cached_reader)
    executor = SafeExecutor()
    executed = []
    execution_lock = threading.Lock()

    async def execute(command, host=None):
        assert command == "exact-retained-operation"
        with execution_lock:
            executed.append(command)
        return {"success": True, "returncode": 0}

    monkeypatch.setattr(executor, "_exec", execute)

    def stale_reader():
        worker.reader = True
        worker.now = start + 3599
        return asyncio.run(executor.run(reference))

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(stale_reader)
        try:
            assert reader_has_payload.wait(timeout=10)
            worker.now = start + 3599
            winner = asyncio.run(executor.run(reference))
            assert winner["success"] is True
            # Negative control: a repeat is already blocked before reclamation.
            repeat = asyncio.run(executor.run(reference))
            assert repeat["blocked"] is True
            assert len(executed) == 1
            if reclaim:
                worker.now = start + 3601
                CommandApprovalStore(storage).cleanup()
        finally:
            resume_reader.set()
        loser = pending.result(timeout=10)

    assert len(executed) == 1, (executed, loser)
    assert loser.get("blocked") is True
    assert loser.get("success") is False
    assert loser.get("returncode") == 1


def test_s3_compatible_server_that_creates_on_missing_if_match_is_refused(clock):
    objects = MemoryStorage()
    storage = S3Storage.__new__(S3Storage)
    storage.bucket = "approval-fixture"

    def broken_put(*, Bucket, Key, Body, ContentType, **kwargs):
        # Model a server violating the required If-Match-on-missing contract.
        if "IfMatch" in kwargs:
            objects.put_bytes(Key, Body)
        elif not objects.put_json_if_absent(Key, json.loads(Body)):
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")

    storage._client = SimpleNamespace(
        put_object=broken_put,
        get_paginator=lambda operation: SimpleNamespace(paginate=lambda **kw: []),
        head_object=lambda **kw: None,
        delete_object=lambda **kw: objects.delete(kw["Key"]),
    )
    with pytest.raises(RuntimeError, match="atomic"):
        CommandApprovalStore(storage).retain("must-not-be-approved")
    assert b"must-not-be-approved" not in retained_bytes(objects)


@pytest.mark.parametrize("transition", ["removed", "changed"])
def test_consumption_requires_the_current_payload_at_the_atomic_boundary(
    backend, clock, monkeypatch, transition
):
    storage, objects = backend
    reference = CommandApprovalStore(storage).retain("operation-must-not-execute")

    def revoke(key):
        if transition == "removed":
            storage.delete(key)
        else:
            storage.put_json(key, {"consumed": True})

    if isinstance(storage, MemoryStorage):
        original = storage.get_json

        def read_then_revoke(key):
            cached = original(key)
            if isinstance(cached, dict) and "command" in cached:
                revoke(key)
            return cached

        monkeypatch.setattr(storage, "get_json", read_then_revoke)
    else:
        # Revoke after the native version/body read, immediately before the
        # conditional write is evaluated by the simulated object server.
        objects.before_conditional_write = revoke

    assert CommandApprovalStore(storage).resolve(reference) is None
    assert b"operation-must-not-execute" not in retained_bytes(objects)
