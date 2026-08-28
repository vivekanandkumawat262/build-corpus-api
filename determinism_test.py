import requests
import json


URL = "http://127.0.0.1:8000/build-corpus"


# ------------------------------------------------------------
# CRC32C
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def make_row(
    id,
    entity,
    eventTime,
    revision,
    text
):
    return {
        "id": id,
        "entity": entity,
        "eventTime": eventTime,
        "revision": revision,
        "text": text,
    }


def make_content(rows):

    return "\n".join(
        json.dumps(
            r,
            ensure_ascii=False,
            separators=(",", ":")
        )
        for r in rows
    )


# ------------------------------------------------------------
# Build a reasonably complicated corpus
# ------------------------------------------------------------

rows = [

    # Normal row
    make_row(
        "100",
        "Alice",
        "2026-01-02T05:30:00+05:30",
        1,
        "Hello World"
    ),

    # Duplicate of the first row.
    # Higher revision should win.
    make_row(
        "101",
        " Alice ",
        "2026-01-02T00:00:00Z",
        2,
        "Hello World"
    ),

    # Unicode / whitespace
    make_row(
        "200",
        "  Ｂｏｂ\u00a0Smith ",
        "2026-03-10T12:00:00.1Z",
        5,
        "  Machine\u2003Learning  "
    ),

    # Another row
    make_row(
        "300",
        "Charlie",
        "2026-05-20T18:30:00.12Z",
        3,
        "Data Science"
    ),

    # Another duplicate with same revision.
    # UTF-8 smallest ID should win.
    make_row(
        "z",
        "DuplicateEntity",
        "2026-06-01T00:00:00Z",
        10,
        "Same text"
    ),

    make_row(
        "a",
        "DuplicateEntity",
        "2026-06-01T00:00:00Z",
        10,
        "Same text"
    ),
]


content = make_content(rows)


payload = {
    "policy": {
        "minTime": "2026-01-01T00:00:00Z",
        "maxTime": "2026-12-31T23:59:59Z",
        "contaminationThreshold": 0.8
    },

    "objects": [
        {
            "uri": "gs://bucket/determinism-test",
            "generation": "123456",
            "fetchedGeneration": "123456",
            "crc32c": crc(content),
            "schemaId": "training-v1",
            "content": content
        }
    ]
}


# ------------------------------------------------------------
# First request
# ------------------------------------------------------------

response1 = requests.post(
    URL,
    json=payload
)

print("First status :", response1.status_code)

data1 = response1.json()


# ------------------------------------------------------------
# Second request
# ------------------------------------------------------------

response2 = requests.post(
    URL,
    json=payload
)

print("Second status:", response2.status_code)

data2 = response2.json()


# ------------------------------------------------------------
# Compare
# ------------------------------------------------------------

print()
print("=" * 60)

if response1.status_code != 200:
    print("FAIL: First request did not return 200")

elif response2.status_code != 200:
    print("FAIL: Second request did not return 200")

elif data1 != data2:
    print("FAIL: Responses are NOT deterministic")

    print()
    print("FIRST RESPONSE:")
    print(
        json.dumps(
            data1,
            indent=2,
            ensure_ascii=False
        )
    )

    print()
    print("SECOND RESPONSE:")
    print(
        json.dumps(
            data2,
            indent=2,
            ensure_ascii=False
        )
    )

else:
    print("PASS: Responses are deterministic")
    print("PASS: Same request produced exactly the same response")

print("=" * 60)