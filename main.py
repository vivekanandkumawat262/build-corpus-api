from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib
import json
import re
import unicodedata
import binascii
from datetime import datetime, timezone


app = FastAPI()


# ============================================================
# CONSTANTS
# ============================================================

OBJECT_CODES = {
    "URI_INVALID",
    "GENERATION_INVALID",
    "GENERATION_MISMATCH",
    "CRC32C_INVALID",
    "CRC32C_MISMATCH",
    "SCHEMA_INVALID",
    "JSONL_INVALID",
}

ROW_CODES = {
    "DUPLICATE",
    "POLICY_INVALID",
    "OUT_OF_WINDOW",
    "TRAIN_CONTAMINATION",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8_bytes(value):
    return value.encode("utf-8")


def utf8_sort_key(value):
    return utf8_bytes(value)


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


def compact_json_bytes(value):
    return compact_json(value).encode("utf-8")


# ============================================================
# GENERATION VALIDATION
# ============================================================

def valid_generation(value):
    """
    Generation must be a decimal string.
    """
    if not isinstance(value, str):
        return False

    return bool(re.fullmatch(r"[0-9]+", value))


# ============================================================
# CRC32C
# ============================================================

# CRC32C Castagnoli lookup table
CRC32C_TABLE = []

POLY = 0x82F63B78

for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ POLY
        else:
            crc >>= 1
    CRC32C_TABLE.append(crc)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data: bytes) -> str:
    return f"{crc32c(data):08x}"


def valid_crc_syntax(value):
    if not isinstance(value, str):
        return False

    return bool(re.fullmatch(r"[0-9a-f]{8}", value))


# ============================================================
# TIMESTAMP
# ============================================================

TIME_RE = re.compile(
    r"^"
    r"\d{4}-\d{2}-\d{2}"
    r"T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})"
    r"$"
)


def parse_timestamp(value):
    """
    Parse required timestamp format.

    Returns:
        datetime in UTC
    or:
        None
    """

    if not isinstance(value, str):
        return None

    match = TIME_RE.fullmatch(value)

    if not match:
        return None

    fraction = match.group(1)
    offset = match.group(2)

    # Validate offset magnitude.
    if offset != "Z":
        sign = offset[0]
        hours = int(offset[1:3])
        minutes = int(offset[4:6])

        if minutes >= 60:
            return None

        if hours > 14:
            return None

        if hours == 14 and minutes != 0:
            return None

        offset_minutes = hours * 60 + minutes

        if sign == "-":
            offset_minutes = -offset_minutes

        from datetime import timedelta

        tz = timezone(timedelta(minutes=offset_minutes))
    else:
        tz = timezone.utc

    # Convert fractional seconds to microseconds.
    if fraction is None:
        microseconds = 0
    else:
        microseconds = int(fraction.ljust(3, "0")) * 1000

    try:
        dt = datetime(
            int(value[0:4]),
            int(value[5:7]),
            int(value[8:10]),
            int(value[11:13]),
            int(value[14:16]),
            int(value[17:19]),
            microseconds,
            tzinfo=tz
        )
    except ValueError:
        return None

    return dt.astimezone(timezone.utc)


def canonical_timestamp(value):
    dt = parse_timestamp(value)

    if dt is None:
        return None

    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.microsecond // 1000:03d}Z"


# ============================================================
# UNICODE CANONICALIZATION
# ============================================================

def canonical_text(value):
    """
    Unicode NFKC
    lowercase
    trim
    collapse Unicode whitespace
    """

    value = unicodedata.normalize("NFKC", value)

    value = value.lower()

    # Unicode whitespace → ASCII space
    value = "".join(
        " " if ch.isspace() else ch
        for ch in value
    )

    # Collapse whitespace
    value = " ".join(value.split())

    return value


# ============================================================
# JSONL PARSING
# ============================================================

REQUIRED_ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}


def parse_jsonl(content):
    """
    Returns:

        rows
        jsonl_invalid
        schema_invalid

    """

    rows = []

    jsonl_invalid = False
    schema_invalid = False

    lines = content.splitlines()

    # Blank lines ignored
    nonblank_lines = [
        line for line in lines
        if line.strip() != ""
    ]

    # Empty file is schema invalid
    if not nonblank_lines:
        return [], False, True

    for line in nonblank_lines:

        try:
            obj = json.loads(line)
        except Exception:
            jsonl_invalid = True
            continue

        # Must be object
        if not isinstance(obj, dict):
            schema_invalid = True
            continue

        # Exactly required keys
        if set(obj.keys()) != REQUIRED_ROW_KEYS:
            schema_invalid = True
            continue

        # Four text fields
        if not isinstance(obj["id"], str):
            schema_invalid = True
            continue

        if not isinstance(obj["entity"], str):
            schema_invalid = True
            continue

        if not isinstance(obj["eventTime"], str):
            schema_invalid = True
            continue

        if not isinstance(obj["text"], str):
            schema_invalid = True
            continue

        # Revision: non-negative safe integer
        revision = obj["revision"]

        if isinstance(revision, bool):
            schema_invalid = True
            continue

        if not isinstance(revision, int):
            schema_invalid = True
            continue

        if revision < 0:
            schema_invalid = True
            continue

        # JavaScript safe integer
        if revision > 9007199254740991:
            schema_invalid = True
            continue

        # eventTime must be valid
        if parse_timestamp(obj["eventTime"]) is None:
            schema_invalid = True
            continue

        rows.append(obj)

    return rows, jsonl_invalid, schema_invalid


# ============================================================
# WORD SET FOR CONTAMINATION
# ============================================================

def word_set(value):
    """
    Lowercase Unicode letter/number word set.

    A word is a maximal sequence of Unicode
    letters/numbers.
    """

    value = value.lower()

    words = []
    current = []

    for ch in value:
        category = unicodedata.category(ch)

        if category.startswith("L") or category.startswith("N"):
            current.append(ch)
        else:
            if current:
                words.append("".join(current))
                current = []

    if current:
        words.append("".join(current))

    return set(words)


def jaccard(a, b):
    """
    Empty / empty = 1
    """

    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# SPLIT
# ============================================================

def determine_split(entity):
    digest = hashlib.sha256(
        entity.encode("utf-8")
    ).digest()

    bucket = digest[0] % 10

    if bucket <= 5:
        return "train"

    if bucket <= 7:
        return "validation"

    return "test"


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):
    if not isinstance(policy, dict):
        return False, None, None, None

    min_time = policy.get("minTime")
    max_time = policy.get("maxTime")
    threshold = policy.get("contaminationThreshold")

    min_dt = parse_timestamp(min_time)
    max_dt = parse_timestamp(max_time)

    # finite numeric [0,1]
    valid_threshold = (
        isinstance(threshold, (int, float))
        and not isinstance(threshold, bool)
        and threshold == threshold
        and threshold != float("inf")
        and threshold != float("-inf")
        and 0 <= threshold <= 1
    )

    if min_dt is None or max_dt is None or not valid_threshold:
        return False, min_dt, max_dt, threshold

    if min_dt > max_dt:
        return False, min_dt, max_dt, threshold

    return True, min_dt, max_dt, threshold


# ============================================================
# OBJECT VALIDATION
# ============================================================

def validate_object(obj):
    codes = []

    uri = obj.get("uri")

    # URI must match gs://bucket/object
    if not isinstance(uri, str):
        codes.append("URI_INVALID")
    else:
        if not re.fullmatch(r"gs://[^/]+/.+", uri):
            codes.append("URI_INVALID")

    generation = obj.get("generation")
    fetched_generation = obj.get("fetchedGeneration")

    gen_valid = valid_generation(generation)
    fetched_valid = valid_generation(fetched_generation)

    if not gen_valid or not fetched_valid:
        codes.append("GENERATION_INVALID")

    if (
        isinstance(generation, str)
        and isinstance(fetched_generation, str)
        and gen_valid
        and fetched_valid
        and generation != fetched_generation
    ):
        codes.append("GENERATION_MISMATCH")

    crc = obj.get("crc32c")

    if not valid_crc_syntax(crc):
        codes.append("CRC32C_INVALID")

    content = obj.get("content")

    # CRC mismatch only if content string
    # and CRC syntax is valid.
    if isinstance(content, str) and valid_crc_syntax(crc):
        calculated = crc32c_hex(content.encode("utf-8"))

        if calculated != crc:
            codes.append("CRC32C_MISMATCH")

    # Schema
    schema_id = obj.get("schemaId")

    if (
        not isinstance(content, str)
        or schema_id != "training-v1"
    ):
        codes.append("SCHEMA_INVALID")

    # Parse content only if content is string
    parsed_rows = []

    if isinstance(content, str):

        rows, jsonl_invalid, schema_invalid = parse_jsonl(content)

        if jsonl_invalid:
            codes.append("JSONL_INVALID")

        if schema_invalid:
            codes.append("SCHEMA_INVALID")

        parsed_rows = rows

    # Sort and deduplicate object codes
    codes = sorted(
        set(codes),
        key=utf8_sort_key
    )

    return codes, parsed_rows


# ============================================================
# ROW OUTPUT
# ============================================================

def output_row(row):
    return {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"],
    }


# ============================================================
# MAIN ENDPOINT
# ============================================================

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # --------------------------------------------------------
    # Parse request JSON
    # --------------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    # Missing policy OR non-array objects
    if (
        not isinstance(body, dict)
        or "policy" not in body
        or "objects" not in body
        or not isinstance(body["objects"], list)
    ):
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"}
        )

    policy = body["policy"]
    objects = body["objects"]

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy_valid, min_dt, max_dt, threshold = validate_policy(policy)

    # --------------------------------------------------------
    # Output containers
    # --------------------------------------------------------

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    rejected_objects = []
    rejected_rows = []
    lineage = []

    # --------------------------------------------------------
    # Process objects
    # --------------------------------------------------------

    for obj in objects:

        # Make sure object itself is dictionary
        if not isinstance(obj, dict):
            # There is no valid URI available.
            rejected_objects.append({
                "uri": None,
                "reasonCodes": [
                    "SCHEMA_INVALID"
                ]
            })
            continue

        codes, rows = validate_object(obj)

        uri = obj.get("uri")

        if codes:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": codes
            })

            # Object rejected completely
            continue

        # Valid object contributes lineage
        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"],
            "schemaId": obj["schemaId"],
        })

        # ----------------------------------------------------
        # Canonicalize rows
        # ----------------------------------------------------

        canonical_rows = []

        for row in rows:

            canonical = {
                "id": row["id"],
                "entity": canonical_text(row["entity"]),
                "eventTime": canonical_timestamp(row["eventTime"]),
                "revision": row["revision"],
                "text": canonical_text(row["text"]),
            }

            canonical_rows.append(canonical)

        # ----------------------------------------------------
        # Deduplication
        # ----------------------------------------------------

        groups = {}

        for row in canonical_rows:

            key = (
                row["entity"],
                row["eventTime"],
                row["text"],
            )

            groups.setdefault(key, []).append(row)

        retained = []

        for key, group in groups.items():

            # Highest revision
            max_revision = max(
                row["revision"]
                for row in group
            )

            candidates = [
                row for row in group
                if row["revision"] == max_revision
            ]

            # UTF-8-byte-smallest ID
            winner = min(
                candidates,
                key=lambda x: utf8_bytes(x["id"])
            )

            retained.append(winner)

            for loser in group:

                if loser is winner:
                    continue

                rejected_rows.append({
                    "id": loser["id"],
                    "reasonCodes": ["DUPLICATE"]
                })

        # ----------------------------------------------------
        # Policy / window
        # ----------------------------------------------------

        for row in retained:

            if not policy_valid:

                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": ["POLICY_INVALID"]
                })

                continue

            row_dt = parse_timestamp(row["eventTime"])

            if row_dt < min_dt or row_dt > max_dt:

                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": ["OUT_OF_WINDOW"]
                })

                continue

            # Put into split
            split = determine_split(row["entity"])

            splits[split].append(row)

    # --------------------------------------------------------
    # Contamination
    # --------------------------------------------------------

    # Build train word sets
    train_wordsets = []

    for row in splits["train"]:

        words = word_set(
            row["entity"] + " " + row["text"]
        )

        train_wordsets.append(words)

    # Validation/test against every train row
    for split_name in ["validation", "test"]:

        kept = []

        for row in splits[split_name]:

            words = word_set(
                row["entity"] + " " + row["text"]
            )

            contaminated = False

            for train_words in train_wordsets:

                similarity = jaccard(
                    words,
                    train_words
                )

                if similarity >= threshold:
                    contaminated = True
                    break

            if contaminated:

                rejected_rows.append({
                    "id": row["id"],
                    "reasonCodes": [
                        "TRAIN_CONTAMINATION"
                    ]
                })

            else:
                kept.append(row)

        splits[split_name] = kept

    # --------------------------------------------------------
    # Deterministic sorting
    # --------------------------------------------------------

    for split_name in splits:

        splits[split_name].sort(
            key=lambda row: (
                utf8_bytes(row["id"]),
                compact_json_bytes(output_row(row))
            )
        )

    # --------------------------------------------------------
    # Rejected row sorting + reason deduplication
    # --------------------------------------------------------

    # Combine same ID reason codes
    rejected_by_id = {}

    for item in rejected_rows:

        rid = item["id"]

        rejected_by_id.setdefault(
            rid,
            set()
        ).update(item["reasonCodes"])

    rejected_rows = [
        {
            "id": rid,
            "reasonCodes": sorted(
                reasons,
                key=utf8_sort_key
            )
        }
        for rid, reasons in rejected_by_id.items()
    ]

    rejected_rows.sort(
        key=lambda item: (
            utf8_bytes(item["id"]),
            compact_json_bytes(item)
        )
    )

    # --------------------------------------------------------
    # Rejected object sorting
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = sorted(
            set(item["reasonCodes"]),
            key=utf8_sort_key
        )

    rejected_objects.sort(
        key=lambda item: (
            utf8_bytes(item["uri"] or ""),
            compact_json_bytes(item)
        )
    )

    # --------------------------------------------------------
    # Lineage sorting
    # --------------------------------------------------------

    lineage.sort(
        key=lambda item: (
            utf8_bytes(item["uri"]),
            compact_json_bytes(item)
        )
    )

    # --------------------------------------------------------
    # JSONL digest
    # --------------------------------------------------------

    digests = {}

    for split_name in ["train", "validation", "test"]:

        serialized = b"".join(
            (
                compact_json(output_row(row)).encode("utf-8")
                + b"\n"
            )
            for row in splits[split_name]
        )

        digests[split_name] = hashlib.sha256(
            serialized
        ).hexdigest()

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {
        "splits": {
            "train": [
                output_row(row)
                for row in splits["train"]
            ],
            "validation": [
                output_row(row)
                for row in splits["validation"]
            ],
            "test": [
                output_row(row)
                for row in splits["test"]
            ],
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": digests,
        "lineage": lineage,
    }