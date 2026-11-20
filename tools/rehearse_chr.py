"""Restore vpn-lists on a disposable CHR and verify the first hourly run against Git."""
import argparse
from collections import Counter
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen
from zipfile import ZipFile

from prepare_restore import git, prepare

IMAGE = "chr-7.25.1.img"
IMAGE_URL = f"https://download.mikrotik.com/routeros/7.25.1/{IMAGE}.zip"
IMAGE_SHA256 = "c78e8e24ca78d7f13496140e600702df07fe5c57d1a5d6d025654c8476ed2ed2"
UPSTREAM = "https://github.com/RokudoFran/vpn-lists.git"
SCHEDULE = '[/system scheduler find where name="vpn-lists-hourly"]'
RUN = "/system script run vpn-lists-v2"
COUNTS = (':put ([:len [/ip firewall address-list find where list="vpn_git"]] . "|" . '
          '[:len [/ip dns static find where comment="git-dns"]])')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_image(directory, archive):
    if archive is None:
        archive = directory / (IMAGE + ".zip")
        with urlopen(IMAGE_URL, timeout=90) as response, archive.open("wb") as dest:
            shutil.copyfileobj(response, dest)
    with archive.open("rb") as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == IMAGE_SHA256,
                "Wrong SHA-256 for the CHR 7.25.1 x86-64 ZIP")
    with ZipFile(archive) as z, z.open(IMAGE) as src, (directory / IMAGE).open("wb") as dest:
        shutil.copyfileobj(src, dest)


def initialize_console(console, password):
    def expect(pattern, timeout=90):
        deadline = time.monotonic() + timeout
        received = b""
        while time.monotonic() < deadline:
            try:
                chunk = console.recv(8192)
            except socket.timeout:
                continue
            require(chunk, "CHR serial console closed")
            received = (received + chunk)[-16000:]
            plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", received)
            match = re.search(pattern, plain, re.I)
            if match:
                return match.group().lower()
        raise RuntimeError(f"CHR serial console timed out waiting for {pattern!r}")

    def send(line):
        console.sendall(line.encode("ascii") + b"\r")

    console.settimeout(1)
    send("")
    expect(rb"CHR Login:")
    send("admin+ct")
    expect(rb"Password:")
    send("")
    prompt = rb"\[y/n\]|new password\s*[:>]|\[admin@CHR\]\s*>"
    answer = expect(prompt)
    if answer == b"[y/n]":
        send("n")
        answer = expect(prompt)
    if b"new password" in answer:
        send(password)
        expect(rb"(repeat|confirm)[^:>\r\n]*password\s*[:>]")
        send(password)
    else:
        send('/user set admin password="' + password + '"')
    expect(rb"\[admin@CHR\]\s*>")


@contextmanager
def virtual_machine(directory, executable, error_log):
    # QEMU connects its serial device to our already-bound listener. The only
    # management endpoint exposed by user-mode NAT is SSH on host loopback.
    with socket.socket() as serial, socket.socket() as reserve:
        serial.bind(("127.0.0.1", 0))
        serial.listen(1)
        serial.settimeout(1)
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        args = [executable, "-machine", "pc,accel=tcg", "-cpu", "max", "-m", "1024",
                "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot",
                "-rtc", "base=utc", "-drive", f"file={IMAGE},format=raw,if=virtio",
                "-serial", f"tcp:127.0.0.1:{serial.getsockname()[1]}",
                "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:22"]
        firmware = Path(executable).parent / "share"
        if (firmware / "bios-256k.bin").is_file():
            args.extend(["-L", str(firmware)])
        reserve.close()
        with error_log.open("wb") as errors:
            vm = subprocess.Popen(args, cwd=directory, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=errors)
            try:
                deadline = time.monotonic() + 120
                while True:
                    require(vm.poll() is None, f"QEMU exited; see {error_log}")
                    require(time.monotonic() < deadline, f"No QEMU serial console; see {error_log}")
                    try:
                        console, _ = serial.accept()
                        break
                    except socket.timeout:
                        continue
                password = secrets.token_urlsafe(24)
                with console:
                    initialize_console(console, password)
                yield port, password
            finally:
                if vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait()


def run(ssh, command):
    # RouterOS may omit the SSH exit status. Require a final success marker.
    marker = "CHR_COMMAND_OK"
    wrapped = ':onerror err in={ ' + command + '; :put "' + marker + '" } do={ :put ("CHR_ERROR " . $err) }'
    _, stdout, stderr = ssh.exec_command(wrapped, timeout=300)
    lines = stdout.read().decode().splitlines()
    error = stderr.read().decode().strip()
    require(not error and lines and lines[-1].strip() == marker,
            f"CHR command failed ({command[:75]}): {error or ' '.join(lines[-3:])}")
    return "\n".join(lines[:-1]).strip()


def upload(ssh, kit, name):
    with ssh.open_sftp() as transfer:
        transfer.put(str(kit / name), name)
    digest = run(ssh, f':put [:convert [/file get "{name}" contents] from=raw to=hex transform=sha512]')
    require(digest == hashlib.sha512((kit / name).read_bytes()).hexdigest(), f"Upload differs: {name}")


def stage(ssh, kit, name):
    print(f"Installing {name}", flush=True)
    result = run(ssh, f':global vlAuditStage "{name}"; /import file-name=stage-lan.rsc')
    require(f"Installed Source stage={name};" in result, f"Stage failed: {result}")
    digest = run(ssh, ':put [:convert [/system script get [find where name="vpn-lists-v2"] source] '
                      'from=raw to=hex transform=sha512]')
    require(digest == hashlib.sha512((kit / f"v2-{name}.txt").read_bytes()).hexdigest(),
            f"Installed Source differs: {name}")


def release(kit):
    values = (kit / "RELEASE.txt").read_text("ascii").splitlines()
    return values[0].removeprefix("commit="), values[1].removeprefix("payload_sha512=")


def status(ssh):
    values = run(ssh, ':global vpnListsV2Version; :global vpnListsV2LastCheck; '
                 ':global vpnListsV2LastVerified; :global vpnListsV2LastError; '
                 ':put ($vpnListsV2Version . "|" . $vpnListsV2LastCheck . "|" . '
                 '$vpnListsV2LastVerified . "|" . $vpnListsV2LastError)').split("|", 3)
    return dict(zip(("version", "last_check", "last_verified", "error"), values, strict=True))


def last_log(ssh, prefix):
    return run(ssh, f':local ids [/log find where topics~"script" and message~"^vpn-lists-v2: {prefix}"]; '
               ':if ([:len $ids]>0) do={:local id [:pick $ids ([:len $ids]-1)]; '
               ':put ([:tostr $id] . "|" . [/log get $id time] . "|" . [/log get $id message])}')


def verify_tables(ssh, kit, output):
    commit, digest = release(kit)
    result = run(ssh, "/import file-name=verify-lan.rsc")
    require(f"MATCH release={commit} " in result and "sha512=" + digest in result, result)
    data = json.loads(json.loads(git("show", f"{commit}:lists/bundle.json"))["payload"])
    nets = [f"{net}|git|false|false" for net in data["vpn_ipv4.txt"]]
    dns = []
    for key, lst, resolver in [("domains_vpn.txt", "vpn_dns", "8.8.8.8"),
                               ("domains_direct.txt", "no_vpn", "77.88.8.8")]:
        dns.extend(f"{name}|FWD|{lst}|{resolver}|true|false|git-dns" for name in data[key])
    for name, menu, where, fields, expected in [
        ("ipv4", "/ip firewall address-list", 'list="vpn_git"', "address comment disabled dynamic", nets),
        ("dns", "/ip dns static", 'comment="git-dns"', "name type address-list forward-to match-subdomain disabled comment", dns),
    ]:
        expr = ' . "|" . '.join(f"[{menu} get $id {field}]" for field in fields.split())
        rows = run(ssh, f":foreach id in=[{menu} find where {where}] do={{:put ({expr})}}").splitlines()
        actual, wanted = Counter(rows), Counter(expected)
        if output:
            table = [fields.replace(" ", "\t"), *(row.replace("|", "\t") for row in sorted(rows))]
            (output / f"{name}.tsv").write_text("\n".join(table) + "\n", encoding="utf-8")
        require(actual == wanted, f"{name}: missing {list((wanted-actual).elements())[:5]}, "
                f"extra {list((actual-wanted).elements())[:5]}")
    require(run(ssh, ':put [/ip dns static get [find where name="router.lan"] address]') == "192.168.13.1",
            "Local DNS record changed")
    return {key: len(rows) for key, rows in data.items()}


def install(ssh, kit):
    device = run(ssh, ':put ([/system resource get board-name] . "|" . [/system resource get version] . "|" . '
                 '[/system resource get architecture-name] . "|" . [/system identity get name])')
    board, version, arch, identity = device.split("|")
    require(board.startswith("CHR") and version.split()[0] == "7.25.1" and (arch, identity) == ("x86_64", "CHR"),
            f"Unexpected guest: {device}")
    for menu in ("/system script", "/system scheduler", "/ip firewall address-list", "/ip dns static"):
        require(run(ssh, f":put [:len [{menu} find]]") == "0", f"Guest already has entries in {menu}")
    print(f"Verified empty guest: {device}", flush=True)
    for command in [
        "/system identity set name=HOME-AX3", "/interface bridge add name=bridge",
        "/ip address add address=192.168.13.1/24 interface=bridge",
        "/ip firewall nat add chain=srcnat src-address=192.168.13.1 out-interface=ether1 action=masquerade",
        '/ip dns static add name=router.lan address=192.168.13.1 comment="CHR local record"',
    ]:
        run(ssh, command)
    for line in (kit / "SHA512SUMS.txt").read_text("ascii").splitlines():
        upload(ssh, kit, line.split("  ")[1])
    for name in ("stage-lan.rsc", "verify-lan.rsc"):
        result = run(ssh, f"/import file-name={name} verbose=yes dry-run")
        require("no syntax errors" in result.lower(), f"Dry import failed: {name}")
    run(ssh, f'/system scheduler add name=vpn-lists-hourly disabled=yes start-time=startup interval=1h '
             f'on-event="{RUN}" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon')
    stage(ssh, kit, "dry-lan")
    run(ssh, RUN)
    require(last_log(ssh, "dry-run OK") and run(ssh, COUNTS) == "0|0", "Dry run failed or wrote entries")
    stage(ssh, kit, "once-lan")
    _, digest = release(kit)
    previous = ""
    for attempt in (1, 2):
        run(ssh, RUN)
        state = status(ssh)
        require(state["version"] == digest and not state["error"] and state["last_verified"] > previous,
                f"Pinned application did not complete: {state}")
        verify_tables(ssh, kit, None)
        print(f"Pinned application {attempt}: Git tables match", flush=True)
        previous = state["last_verified"]
    stage(ssh, kit, "hourly-lan")
    require(run(ssh, f":put [/system scheduler get {SCHEDULE} run-count]") == "0", "Scheduler already ran")
    baseline = {"guest": device, "run_count_before_enable": 0,
                "status": state, "log": last_log(ssh, "reconciled")}
    require(baseline["log"], "Missing reconciliation log before enabling scheduler")
    run(ssh, f"/system scheduler enable {SCHEDULE}")
    baseline["scheduler"] = run(ssh, '/system scheduler print detail where name="vpn-lists-hourly"')
    print(baseline["scheduler"], flush=True)
    return baseline


def observed_release(kit, version):
    commit, pinned = release(kit)
    if version == pinned:
        return kit
    # main can publish while the guest is waiting. Compare to the immutable
    # release actually applied, including when a second publication followed it.
    git("fetch", "--quiet", "--no-tags", UPSTREAM, "refs/heads/main")
    for rev in git("rev-list", "FETCH_HEAD", "--not", commit, "--", "lists").decode().splitlines():
        if json.loads(git("show", f"{rev}:lists/bundle.json"))["sha512"] == version:
            updated = kit.parent / "scheduled-kit"
            prepare(updated, rev)
            return updated
    raise RuntimeError(f"No published Git payload matches scheduled version {version}")


def wait_for_schedule(connect, baseline, transport_errors):
    # Count observations, not host clock jumps during suspend. Never run the updater here.
    for _ in range(300):
        time.sleep(15)
        try:
            with closing(connect()) as ssh:
                counter = run(ssh, f":put [/system scheduler get {SCHEDULE} run-count]")
                if counter == "0":
                    continue
                require(counter == "1", f"Missed the first scheduled run (run-count={counter})")
                jobs = run(ssh, ':put [:len [/system script job find where script="vpn-lists-v2"]]')
                if jobs != "0":
                    continue
                state = status(ssh)
                require(not state["error"], f"Scheduled run failed: {state['error']}")
                if state["last_check"] == baseline["status"]["last_check"]:
                    continue
                log = last_log(ssh, "reconciled")
                require(state["last_verified"] >= state["last_check"]
                        and state["last_verified"] != baseline["status"]["last_verified"]
                        and log and log != baseline["log"],
                        f"No fresh successful reconciliation: {state}")
                return state, log
        except transport_errors as exc:
            print(f"SSH observation unavailable: {type(exc).__name__}", flush=True)
    raise RuntimeError("No completed first scheduled run in 300 observations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for results and QEMU diagnostics")
    parser.add_argument("--image-zip", type=Path, help="previously downloaded official CHR ZIP")
    parser.add_argument("--qemu", default="qemu-system-x86_64", help="QEMU binary name or path")
    args = parser.parse_args()
    import paramiko
    executable = shutil.which(args.qemu)
    require(executable, f"QEMU not found: {args.qemu}")
    executable = str(Path(executable).resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        kit = directory / "kit"
        prepare(kit, None)
        extract_image(directory, args.image_zip)
        with virtual_machine(directory, executable, output / "qemu.log") as (port, password):
            # This client retains the ephemeral VM host key across reconnections.
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            def connect():
                try:
                    client.connect("127.0.0.1", port=port, username="admin", password=password,
                                   allow_agent=False, look_for_keys=False, timeout=10, auth_timeout=15)
                    client.set_missing_host_key_policy(paramiko.RejectPolicy())
                    return client
                except BaseException:
                    client.close()
                    raise

            # On first boot the console can become ready before DHCP and sshd.
            for attempt in range(12):
                try:
                    ssh = connect()
                    break
                except paramiko.AuthenticationException:
                    raise
                except (OSError, EOFError, paramiko.SSHException):
                    if attempt == 11:
                        raise
                    time.sleep(2)
            with closing(ssh):
                baseline = install(ssh, kit)
            (output / "before.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")
            state, log = wait_for_schedule(connect, baseline, (OSError, EOFError, paramiko.SSHException))
            final = observed_release(kit, state["version"])
            with closing(connect()) as ssh:
                if final != kit:
                    upload(ssh, final, "verify-lan.rsc")
                counts = verify_tables(ssh, final, output)
                scheduler = run(ssh, '/system scheduler print detail where name="vpn-lists-hourly"')
                require(re.search(r"\brun-count=1\b", scheduler), "Scheduler ran again during verification")
            commit, digest = release(final)
            result = {"result": "PASS", "observed_utc": utc_now(), "checkout": git("rev-parse", "HEAD").decode().strip(),
                      "pinned_commit": release(kit)[0], "scheduled_commit": commit, "sha512": digest,
                      "scheduler_count": 1, "scheduler": scheduler, "status": state, "log": log, "counts": counts}
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"PASS {commit} {counts}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, ImportError, subprocess.CalledProcessError) as error:
        sys.exit(f"Rehearsal failed: {error}")
