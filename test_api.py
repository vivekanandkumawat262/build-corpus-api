import requests
import json


content = """{"id":"1","entity":"Alice","eventTime":"2026-01-02T05:30:00+05:30","revision":1,"text":"Hello World"}
{"id":"2","entity":"Bob","eventTime":"2026-01-03T10:00:00Z","revision":1,"text":"Machine Learning"}
"""


def crc32c(data: bytes) -> int:
    table = []

    poly = 0x82F63B78

    for i in range(256):
        crc = i

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1

        table.append(crc)

    crc = 0xFFFFFFFF

    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


crc = f"{crc32c(content.encode('utf-8')):08x}"


payload = {
    "policy": {
        "minTime": "2026-01-01T00:00:00Z",
        "maxTime": "2026-12-31T23:59:59Z",
        "contaminationThreshold": 0.8
    },
    "objects": [
        {
            "uri": "gs://bucket/object",
            "generation": "123",
            "fetchedGeneration": "123",
            "crc32c": crc,
            "schemaId": "training-v1",
            "content": content
        }
    ]
}


response = requests.post(
    "http://127.0.0.1:8000/build-corpus",
    json=payload
)

print(response.status_code)

print(
    json.dumps(
        response.json(),
        indent=2,
        ensure_ascii=False
    )
)