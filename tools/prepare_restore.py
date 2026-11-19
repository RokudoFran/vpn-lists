"""Build a HOME-AX3 restore kit pinned to published Git objects."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

from verify_bundle import ROOT, verify

BASE = b"https://raw.githubusercontent.com/RokudoFran/vpn-lists/"
HOURLY_SHA512 = "445b66443cb56235bdd23c08d89dae6fbcaabdd95b7808be0ae7ec71e4193c8355e5e838d0f06ee81b6dc9e0f146919843ba9a42c929200bd66ffd69bd054af2"


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def replace_once(data, marker, new):
    if data.count(marker) != 1:
        raise ValueError(f"expected one occurrence of {marker!r}")
    return data.replace(marker, new)


def prepare(output, ref):
    if output.exists() or output.is_symlink():
        raise ValueError(f"output already exists: {output}")
    if ref is None:
        ref = git("log", "-1", "--format=%H", "HEAD", "--", "lists").decode().strip()
    commit = git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
    digest, counts = verify(lambda name: git("show", f"{commit}:lists/{name}"))
    router = ROOT / "router"
    hourly = (router / "vpn-lists-v2.rsc").read_bytes()
    if hashlib.sha512(hourly).hexdigest() != HOURLY_SHA512:
        raise ValueError("hourly Source differs from the verified HOME-AX3 version")
    once = replace_once(hourly, BASE + b"main/lists/bundle.json", BASE + commit.encode() + b"/lists/bundle.json")
    dry = replace_once(once, b"\n:local applyChanges true\n", b"\n:local applyChanges false\n")
    stages = {"dry-lan": dry, "once-lan": once, "hourly-lan": hourly}
    files = {f"v2-{name}.txt": source for name, source in stages.items()}
    hashes = ";".join(f'"{name}"="{hashlib.sha512(source).hexdigest()}"' for name, source in stages.items())
    files["stage-lan.rsc"] = replace_once((router / "stage-lan.rsc.in").read_bytes(), b"@SOURCE_HASHES@", hashes.encode())
    verifier = replace_once((router / "verify-lan.rsc.in").read_bytes(), b"@COMMIT@", commit.encode())
    files["verify-lan.rsc"] = replace_once(verifier, b"@PAYLOAD_SHA512@", digest.encode())
    summary = f"commit={commit}\npayload_sha512={digest}\nIPv4={counts[0]} VPN={counts[1]} Direct={counts[2]}\n"
    sums = "".join(f"{hashlib.sha512(data).hexdigest()}  {name}\n" for name, data in files.items())
    # Publish a complete directory. A failed check or interrupted write cannot mix kits.
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        kit = Path(temp) / "kit"
        kit.mkdir()
        for name, data in files.items():
            (kit / name).write_bytes(data)
        (kit / "SHA512SUMS.txt").write_bytes(sums.encode("ascii"))
        (kit / "RELEASE.txt").write_bytes(summary.encode("ascii"))
        kit.rename(output)
    print(summary, end="")
    print(f"Restore kit: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory in an existing parent")
    parser.add_argument("--ref", help="data commit or ref, default: last lists change in this checkout")
    args = parser.parse_args()
    try:
        prepare(args.output.absolute(), args.ref)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Preparation failed: {exc}")
