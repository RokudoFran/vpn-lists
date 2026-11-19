"""Check the published bundle against its three text lists and version.txt."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Keep this order for the legacy version hash.
LIMITS = {"vpn_ipv4.txt": (50, 5000), "domains_vpn.txt": (20, 1000), "domains_direct.txt": (5, 1000)}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def verify(read):
    raw = read("bundle.json")
    if len(raw) > 60000:
        raise ValueError("bundle exceeds RouterOS size limit")
    envelope = json.loads(raw, object_pairs_hook=unique_keys)
    if not isinstance(envelope, dict) or type(envelope.get("schema")) is not int or envelope["schema"] != 1:
        raise ValueError("expected bundle schema 1")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ValueError("expected ASCII payload string")
    digest = hashlib.sha512(payload.encode("ascii")).hexdigest()
    if digest != envelope.get("sha512"):
        raise ValueError("SHA-512 of ASCII payload differs from envelope")
    lists = json.loads(payload, object_pairs_hook=unique_keys)
    if not isinstance(lists, dict) or lists.keys() != LIMITS.keys():
        raise ValueError("unexpected payload fields")
    legacy = hashlib.sha256()
    counts = []
    for name, (minimum, maximum) in LIMITS.items():
        rows = lists[name]
        if not isinstance(rows, list) or not minimum <= len(rows) <= maximum:
            raise ValueError(f"row count outside router limits in {name}")
        if any(not isinstance(r, str) or r.split() != [r] for r in rows):
            raise ValueError(f"invalid rows in {name}")
        if len(set(rows)) != len(rows):
            raise ValueError(f"duplicate rows in {name}")
        data = read(name)
        if data != ("\n".join(rows) + "\n").encode("ascii"):
            raise ValueError(f"{name} differs from bundle")
        legacy.update(data)
        counts.append(len(rows))
    if read("version.txt") != (legacy.hexdigest() + "\n").encode("ascii"):
        raise ValueError("legacy SHA-256 differs from version.txt")
    return digest, counts


if __name__ == "__main__":
    try:
        digest, counts = verify(lambda name: (ROOT / "lists" / name).read_bytes())
    except (ValueError, OSError) as exc:
        raise SystemExit(f"Verification failed: {exc}")
    print(f"Verified: IPv4={counts[0]} VPN={counts[1]} Direct={counts[2]} SHA-512={digest}")
