import requests
import json
import hashlib
import unicodedata
import re
from datetime import datetime, timezone, timedelta


BASE_URL = "http://127.0.0.1:8000/build-corpus"


# ============================================================
# CRC32C
# ============================================================

POLY = 0x82F63B78
TABLE = []

for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ POLY
        else:
            crc >>= 1
    TABLE.append(crc)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in data:
        crc = TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def crc(content):
    return f"{crc32c(content.encode('utf-8')):08x}"


# ============================================================
# HELPERS
# ============================================================

def make_object(
    content,
    uri="gs://bucket/object",
    generation="123",
    fetchedGeneration="123",
    schemaId="training-v1",
    crc32c_value=None,
):
    if crc32c_value is None:
        crc32c_value = crc(content)

    return {
        "uri": uri,
        "generation": generation,
        "fetchedGeneration": fetchedGeneration,
        "crc32c": crc32c_value,
        "schemaId": schemaId,
        "content": content,
    }


def request(payload):
    r = requests.post(BASE_URL, json=payload)

    try:
        data = r.json()
    except Exception:
        data = r.text

    return r.status_code, data


def policy(
    minTime="2026-01-01T00:00:00Z",
    maxTime="2026-12-31T23:59:59Z",
    threshold=0.8,
):
    return {
        "minTime": minTime,
        "maxTime": maxTime,
        "contaminationThreshold": threshold,
    }


def row(
    id="1",
    entity="Alice",
    eventTime="2026-01-02T00:00:00Z",
    revision=1,
    text="Hello World",
):
    return {
        "id": id,
        "entity": entity,
        "eventTime": eventTime,
        "revision": revision,
        "text": text,
    }


def jsonl(*rows):
    return "\n".join(
        json.dumps(
            r,
            ensure_ascii=False,
            separators=(",", ":")
        )
        for r in rows
    )


def check(name, condition, details=""):
    if condition:
        print(f"PASS  {name}")
    else:
        print(f"FAIL  {name}")
        if details:
            print("      ", details)

    return condition


# ============================================================
# TEST 1
# INVALID TOP LEVEL
# ============================================================

def test_invalid_top_level():

    status, data = request({})

    check(
        "Missing policy/objects returns 400",
        status == 400 and data == {"error": "INVALID_INPUT"},
        str(data)
    )

    status, data = request({
        "policy": policy(),
        "objects": "not-array"
    })

    check(
        "Non-array objects returns 400",
        status == 400 and data == {"error": "INVALID_INPUT"},
        str(data)
    )


# ============================================================
# TEST 2
# URI VALIDATION
# ============================================================

def test_uri():

    content = jsonl(row())

    obj = make_object(
        content,
        uri="http://bucket/object"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Invalid URI",
        status == 200 and "URI_INVALID" in codes,
        str(data)
    )


# ============================================================
# TEST 3
# GENERATIONS
# ============================================================

def test_generations():

    content = jsonl(row())

    obj = make_object(
        content,
        generation="abc"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Invalid generation",
        "GENERATION_INVALID" in codes,
        str(codes)
    )

    obj = make_object(
        content,
        generation="123",
        fetchedGeneration="456"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Generation mismatch",
        "GENERATION_MISMATCH" in codes,
        str(codes)
    )


# ============================================================
# TEST 4
# CRC
# ============================================================

def test_crc():

    content = jsonl(row())

    # Invalid syntax
    obj = make_object(
        content,
        crc32c_value="123"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Invalid CRC syntax",
        "CRC32C_INVALID" in codes,
        str(codes)
    )

    # Valid syntax but wrong checksum
    obj = make_object(
        content,
        crc32c_value="deadbeef"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "CRC mismatch",
        "CRC32C_MISMATCH" in codes,
        str(codes)
    )


# ============================================================
# TEST 5
# SCHEMA
# ============================================================

def test_schema():

    # Wrong schema ID
    content = jsonl(row())

    obj = make_object(
        content,
        schemaId="wrong-schema"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Wrong schema ID",
        "SCHEMA_INVALID" in codes,
        str(codes)
    )

    # Empty content
    obj = make_object(
        ""
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Empty JSONL",
        "SCHEMA_INVALID" in codes,
        str(codes)
    )


# ============================================================
# TEST 6
# JSONL INVALID
# ============================================================

def test_jsonl():

    content = '{"id":"1","entity":"Alice","eventTime":"2026-01-01T00:00:00Z","revision":1,"text":"hello"\n'

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    check(
        "Invalid JSONL",
        "JSONL_INVALID" in codes,
        str(codes)
    )


# ============================================================
# TEST 7
# TIMESTAMP
# ============================================================

def test_timestamps():

    content = jsonl(
        row(
            eventTime="2026-01-02T05:30:00+05:30"
        )
    )

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    output = data["splits"]["train"] + \
             data["splits"]["validation"] + \
             data["splits"]["test"]

    found = any(
        r["eventTime"] ==
        "2026-01-02T00:00:00.000Z"
        for r in output
    )

    check(
        "Timestamp converted to UTC",
        found,
        str(data)
    )


# ============================================================
# TEST 8
# UNICODE CANONICALIZATION
# ============================================================

def test_unicode():

    content = jsonl(
        row(
            entity="  ＡＬＩＣＥ \u00a0 Smith  ",
            text="  Hello\u2003WORLD  "
        )
    )

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    output = data["splits"]["train"] + \
             data["splits"]["validation"] + \
             data["splits"]["test"]

    if output:

        r = output[0]

        passed = (
            r["entity"] == "alice smith"
            and r["text"] == "hello world"
        )

    else:
        passed = False

    check(
        "Unicode NFKC/lower/whitespace",
        passed,
        str(data)
    )


# ============================================================
# TEST 9
# DEDUPLICATION
# ============================================================

def test_deduplication():

    r1 = row(
        id="z",
        revision=1
    )

    r2 = row(
        id="a",
        revision=2
    )

    content = jsonl(r1, r2)

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    output = data["splits"]["train"] + \
             data["splits"]["validation"] + \
             data["splits"]["test"]

    ids = [r["id"] for r in output]

    duplicate_ids = [
        r["id"]
        for r in data["rejectedRows"]
        if "DUPLICATE" in r["reasonCodes"]
    ]

    check(
        "Highest revision wins",
        "a" in ids and "z" in duplicate_ids,
        str(data)
    )


# ============================================================
# TEST 10
# SAME REVISION → SMALLEST UTF-8 ID
# ============================================================

def test_duplicate_id_order():

    r1 = row(
        id="z",
        revision=5
    )

    r2 = row(
        id="a",
        revision=5
    )

    content = jsonl(r1, r2)

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    output = data["splits"]["train"] + \
             data["splits"]["validation"] + \
             data["splits"]["test"]

    ids = [r["id"] for r in output]

    rejected = [
        r["id"]
        for r in data["rejectedRows"]
        if "DUPLICATE" in r["reasonCodes"]
    ]

    check(
        "UTF-8-smallest ID wins",
        "a" in ids and "z" in rejected,
        str(data)
    )


# ============================================================
# TEST 11
# INVALID POLICY
# ============================================================

def test_policy():

    content = jsonl(row())

    obj = make_object(content)

    bad_policy = {
        "minTime": "invalid",
        "maxTime": "2026-12-31T23:59:59Z",
        "contaminationThreshold": 0.8
    }

    status, data = request({
        "policy": bad_policy,
        "objects": [obj]
    })

    rejected = data["rejectedRows"]

    check(
        "Invalid policy rejects retained row",
        any(
            "POLICY_INVALID" in r["reasonCodes"]
            for r in rejected
        ),
        str(data)
    )


# ============================================================
# TEST 12
# OUT OF WINDOW
# ============================================================

def test_window():

    content = jsonl(
        row(
            eventTime="2025-01-01T00:00:00Z"
        )
    )

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    rejected = data["rejectedRows"]

    check(
        "Out-of-window row rejected",
        any(
            "OUT_OF_WINDOW" in r["reasonCodes"]
            for r in rejected
        ),
        str(data)
    )


# ============================================================
# TEST 13
# EMPTY SPLIT DIGEST
# ============================================================

def test_empty_digest():

    content = ""

    # We need a valid object but empty content is schema invalid,
    # so instead use a valid row and force a policy rejection.

    content = jsonl(row())

    obj = make_object(content)

    bad_policy = {
        "minTime": "2027-01-01T00:00:00Z",
        "maxTime": "2027-12-31T23:59:59Z",
        "contaminationThreshold": 0.8
    }

    status, data = request({
        "policy": bad_policy,
        "objects": [obj]
    })

    empty_sha256 = hashlib.sha256(b"").hexdigest()

    check(
        "Empty split uses SHA256(empty bytes)",
        data["digests"]["train"] == empty_sha256,
        str(data["digests"])
    )


# ============================================================
# TEST 14
# DIGEST FORMAT
# ============================================================

def test_digest_format():

    content = jsonl(row())

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    digests = data["digests"]

    passed = all(
        isinstance(d, str)
        and len(d) == 64
        and re.fullmatch(r"[0-9a-f]{64}", d)
        for d in digests.values()
    )

    check(
        "Digest is lowercase SHA256 hex",
        passed,
        str(digests)
    )


# ============================================================
# TEST 15
# EXACT RESPONSE SHAPE
# ============================================================

def test_response_shape():

    content = jsonl(row())

    obj = make_object(content)

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    expected = {
        "splits",
        "rejectedObjects",
        "rejectedRows",
        "digests",
        "lineage"
    }

    passed = (
        status == 200
        and set(data.keys()) == expected
        and set(data["splits"].keys()) ==
            {"train", "validation", "test"}
        and set(data["digests"].keys()) ==
            {"train", "validation", "test"}
    )

    check(
        "Exact top-level response shape",
        passed,
        str(data.keys())
    )


# ============================================================
# TEST 16
# LINEAGE
# ============================================================

def test_lineage():

    content = jsonl(row())

    obj = make_object(
        content,
        uri="gs://bucket/test-object",
        generation="999",
        fetchedGeneration="999"
    )

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    lineage = data["lineage"]

    passed = (
        len(lineage) == 1
        and lineage[0]["uri"] == "gs://bucket/test-object"
        and lineage[0]["generation"] == "999"
        and lineage[0]["crc32c"] == crc(content)
        and lineage[0]["schemaId"] == "training-v1"
    )

    check(
        "Lineage generated correctly",
        passed,
        str(lineage)
    )

# ============================================================
# TEST 17
# OBJECT WITH MULTIPLE ERRORS
# ============================================================

def test_multiple_object_errors():

    content = jsonl(row())

    obj = {
        "uri": "bad-uri",
        "generation": "abc",
        "fetchedGeneration": "xyz",
        "crc32c": "123",
        "schemaId": "wrong",
        "content": content,
    }

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    expected = {
        "URI_INVALID",
        "GENERATION_INVALID",
        "CRC32C_INVALID",
        "SCHEMA_INVALID",
    }

    check(
        "Multiple independent object errors emitted",
        expected.issubset(set(codes)),
        str(codes)
    )


# ============================================================
# TEST 18
# REASON CODE SORTING
# ============================================================

def test_reason_sorting():

    content = jsonl(row())

    obj = {
        "uri": "bad",
        "generation": "abc",
        "fetchedGeneration": "xyz",
        "crc32c": "123",
        "schemaId": "wrong",
        "content": content,
    }

    status, data = request({
        "policy": policy(),
        "objects": [obj]
    })

    codes = data["rejectedObjects"][0]["reasonCodes"]

    sorted_codes = sorted(
        set(codes),
        key=lambda x: x.encode("utf-8")
    )

    check(
        "Reason codes sorted/deduplicated",
        codes == sorted_codes,
        str(codes)
    )


# ============================================================
# RUN EVERYTHING
# ============================================================

tests = [
    test_invalid_top_level,
    test_uri,
    test_generations,
    test_crc,
    test_schema,
    test_jsonl,
    test_timestamps,
    test_unicode,
    test_deduplication,
    test_duplicate_id_order,
    test_policy,
    test_window,
    test_empty_digest,
    test_digest_format,
    test_response_shape,
    test_lineage,
    test_multiple_object_errors,
    test_reason_sorting,
]


print()
print("=" * 60)
print("BUILD-CORPUS GRADER TESTS")
print("=" * 60)
print()

passed = 0

for test in tests:

    try:
        before = passed

        result = test()

        # We count manually below using output only.
        # Each test prints PASS/FAIL.

    except Exception as e:
        print(f"FAIL  {test.__name__}")
        print("      Exception:", repr(e))

print()
print("=" * 60)
print("TESTING COMPLETE")
print("=" * 60)