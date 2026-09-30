#!/usr/bin/env python3
"""Собирает IP-префиксы и домены по services.yaml + manual.txt в простые текстовые списки.

    python collector.py            собрать списки (нужна сеть) и записать lists/ и reports/
    python collector.py --check    только проверить services.yaml и manual.txt, без сети
    FORCE=1 python collector.py    записать, даже если списки изменились подозрительно сильно

Пока не пройдены все проверки, ничего не пишется: обновляется либо всё, либо ничего.
"""
import hashlib, ipaddress, json, os, pathlib, re, sys, time, urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent

# ---- Пороги защиты ----------------------------------------------------------
MIN_PREFIXES = 50          # меньше подсетей не бывает: значит, сломался сбор
MIN_VPN_DOMAINS = 20
MIN_DIRECT_DOMAINS = 5
MAX_SHRINK = 0.25          # объём адресов и число доменов не падают больше чем на 25% за раз
MAX_GROW = 0.25            # и объём адресов не растёт больше чем на 25% за раз
SOURCE_MIN_SHARE = 0.5     # источник не может отдать меньше половины прошлого числа префиксов
MANUAL_MIN_PREFIXLEN = 12  # ручная запись шире /12 — почти наверняка опечатка в маске
SOURCE_MIN_PREFIXLEN = 8   # шире /8 из внешнего источника не бывает — значит, пришёл мусор

RIPE_ASN = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}&sourceapp=vpn-lists"
RIPE_WHO = "https://stat.ripe.net/data/prefix-overview/data.json?resource={}&sourceapp=vpn-lists"
SERVICE_KEYS = {"enabled", "asn", "sources", "prefixes", "domains"}
# Строчная латиница, цифры и дефисы, минимум одна точка. Кириллические домены — в виде xn--.
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Fail(Exception):
    """Ошибка, после которой ничего не записываем."""


# ---- Сеть -------------------------------------------------------------------
def get(url, as_json=True, attempts=3):
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-lists-collector"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read().decode("utf-8")
            return json.loads(data) if as_json else data
        except Exception as e:
            print(f"{url}: попытка {attempt} не удалась: {e}", file=sys.stderr)
            if attempt < attempts:
                time.sleep(5)
    raise Fail(f"Не удалось получить {url}")


# Официальные списки IP от самих компаний
SOURCES = {
    "cloudflare": lambda: get("https://www.cloudflare.com/ips-v4", as_json=False).split(),
    "cloudfront": lambda: [p["ip_prefix"] for p in get("https://ip-ranges.amazonaws.com/ip-ranges.json")["prefixes"]
                           if p["service"] == "CLOUDFRONT"],
    "fastly":     lambda: get("https://api.fastly.com/public-ip-list")["addresses"],
}


def asn_prefixes(asn):
    d = get(RIPE_ASN.format(asn))
    if d.get("status", "ok") != "ok":
        raise Fail(f"RIPEstat по AS{asn} ответил status={d.get('status')!r}")
    return [p["prefix"] for p in d["data"]["prefixes"]]


def whois(net):
    try:
        d = get(RIPE_WHO.format(net), attempts=2)["data"]
    except (Fail, KeyError, TypeError):
        return "не удалось узнать"
    asns = d.get("asns") or []
    if asns:
        return ", ".join(f"AS{a['asn']} {a['holder']}" for a in asns)
    return "не анонсируется (никто не маршрутизирует)"


# ---- Разбор -----------------------------------------------------------------
def parse_strict(text, where):
    """Запись, которую писал человек: любая странность — ошибка, а не молчаливый пропуск.
    strict=True ловит опечатку в маске: «185.135.84.0/2» вместо «/22» даёт host bits set."""
    try:
        n = ipaddress.ip_network(text.strip())
    except ValueError as e:
        raise Fail(f"{where}: {text!r}: {e}")
    if n.version != 4:
        raise Fail(f"{where}: {n}: нужен IPv4")
    if not n.is_global:
        raise Fail(f"{where}: {n}: не публичная сеть")
    if n.prefixlen < MANUAL_MIN_PREFIXLEN:
        raise Fail(f"{where}: {n}: шире /{MANUAL_MIN_PREFIXLEN} — похоже на опечатку в маске")
    return n


def parse_source(items, where):
    """Данные из внешнего источника: непонятное пропускаем, явный мусор — ошибка."""
    out = []
    for p in items:
        try:
            n = ipaddress.ip_network(str(p).strip(), strict=False)
        except ValueError:
            print(f"{where}: пропускаю непонятное {p!r}", file=sys.stderr)
            continue
        if n.version != 4 or not n.is_global:
            continue
        if n.prefixlen < SOURCE_MIN_PREFIXLEN:
            raise Fail(f"{where}: источник вернул {n} — шире /{SOURCE_MIN_PREFIXLEN} так не бывает")
        out.append(n)
    return out


def norm_domain(d, where):
    if not isinstance(d, str):
        raise Fail(f"{where}: {d!r} — домен должен быть строкой")
    x = d.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(x):
        raise Fail(f"{where}: {d!r} — не похоже на домен (латиница; кириллические — в виде xn--)")
    return x


def parents(domain):
    """a.b.example.com -> [b.example.com, example.com]"""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


# ---- Конфигурация -----------------------------------------------------------
def load_config(path):
    """Читает services.yaml и проверяет структуру: опечатка в ключе — ошибка, а не тихий пропуск."""
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise Fail(f"{path.name}: ожидаются разделы services и no_vpn")
    unknown = set(cfg) - {"services", "no_vpn"}
    if unknown:
        raise Fail(f"{path.name}: неизвестные разделы {sorted(unknown)} — опечатка?")
    services = cfg.get("services")
    if not isinstance(services, dict) or not services:
        raise Fail(f"{path.name}: нет раздела services")
    for name, s in services.items():
        where = f"services.{name}"
        if not isinstance(s, dict):
            raise Fail(f"{where}: ожидается словарь")
        bad = set(s) - SERVICE_KEYS
        if bad:
            raise Fail(f"{where}: неизвестные ключи {sorted(bad)} — опечатка? Допустимы: {sorted(SERVICE_KEYS)}")
        if not isinstance(s.get("enabled"), bool):
            raise Fail(f"{where}: нужно явно enabled: true или enabled: false")
        for key in ("asn", "sources", "prefixes", "domains"):
            if s.get(key) is not None and not isinstance(s[key], list):
                raise Fail(f"{where}.{key}: ожидается список в [квадратных скобках]")
        for asn in s.get("asn") or []:
            if isinstance(asn, bool) or not isinstance(asn, int) or not 0 < asn < 2**32:
                raise Fail(f"{where}.asn: {asn!r} — не номер AS")
        for src in s.get("sources") or []:
            if src not in SOURCES:
                raise Fail(f"{where}.sources: {src!r} — такого источника нет, есть {sorted(SOURCES)}")
        # проверяем и у выключенных сервисов: опечатка не должна ждать, пока сервис включат
        s["prefixes"] = [parse_strict(str(p), f"{where}.prefixes") for p in s.get("prefixes") or []]
        s["domains"] = [norm_domain(d, f"{where}.domains") for d in s.get("domains") or []]
    no_vpn = cfg.get("no_vpn")
    if not isinstance(no_vpn, dict) or set(no_vpn) != {"domains"} or not isinstance(no_vpn["domains"], list):
        raise Fail(f"{path.name}: раздел no_vpn должен выглядеть так: no_vpn: {{domains: [...]}}")
    no_vpn["domains"] = [norm_domain(d, "no_vpn.domains") for d in no_vpn["domains"]]
    return cfg


def read_manual(path):
    """manual.txt -> [(подсеть, зачем)]. «Зачем» — комментарий в строке, иначе ближайший заголовок выше."""
    if not path.exists():
        return []
    entries, seen, section = [], set(), ""
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            section = line.lstrip("#").strip()
            continue
        body, _, note = line.partition("#")
        net = parse_strict(body, f"{path.name}:{no}")
        if net in seen:
            raise Fail(f"{path.name}:{no}: {net} уже есть выше")
        seen.add(net)
        entries.append((net, note.strip() or section))
    return entries


def drop_nested(domains, label):
    """Роутер ставит FWD с match-subdomain, так что sub.example.com рядом с example.com лишний."""
    s = set(domains)
    keep = []
    for d in sorted(s):
        parent = next((p for p in parents(d) if p in s), None)
        if parent:
            print(f"{label}: {d} уже покрыт {parent}, пропускаю")
        else:
            keep.append(d)
    return keep


def build_domains(cfg):
    vpn = drop_nested([d for s in cfg["services"].values() if s["enabled"] for d in s["domains"]], "VPN")
    direct = drop_nested(cfg["no_vpn"]["domains"], "no_vpn")
    vs, ds = set(vpn), set(direct)
    clash = sorted(vs & ds)
    clash += sorted(f"{d} (внутри {p})" for d in vs for p in parents(d) if p in ds)
    clash += sorted(f"{d} (внутри {p})" for d in ds for p in parents(d) if p in vs)
    if clash:
        raise Fail("Домен одновременно в VPN и в no_vpn, на роутере неочевидно, какая FWD-запись сработает: "
                   + ", ".join(clash))
    return vpn, direct


# ---- Сбор и проверки --------------------------------------------------------
def collect(cfg):
    """Префиксы всех включённых сервисов -> (подсети, {источник: число префиксов})."""
    nets, stats = [], {}
    for name, s in cfg["services"].items():
        if not s["enabled"]:
            continue
        for asn in s.get("asn") or []:
            got = parse_source(asn_prefixes(asn), f"{name}: AS{asn}")
            stats[f"{name}:AS{asn}"] = len(got)
            nets += got
        for src in s.get("sources") or []:
            got = parse_source(SOURCES[src](), f"{name}: {src}")
            stats[f"{name}:{src}"] = len(got)
            nets += got
        if s["prefixes"]:
            stats[f"{name}:prefixes"] = len(s["prefixes"])
            nets += s["prefixes"]
    for key, n in stats.items():
        print(f"{key} -> {n} префиксов")
        if n == 0:
            print(f"ВНИМАНИЕ: {key} не дал ни одного префикса", file=sys.stderr)
    return nets, stats


def read_previous(lists_dir, reports_dir):
    """То, что уже лежит в репо и раздано роутеру: с этим сравниваем новый сбор."""
    prev = {}
    f = lists_dir / "vpn_ipv4.txt"
    if f.exists():
        prev["addresses"] = sum(ipaddress.ip_network(x).num_addresses
                                for x in f.read_text(encoding="utf-8").split())
    for key, name in (("vpn_domains", "domains_vpn.txt"), ("direct_domains", "domains_direct.txt")):
        p = lists_dir / name
        if p.exists():
            prev[key] = len(p.read_text(encoding="utf-8").split())
    s = reports_dir / "stats.json"
    if s.exists():
        prev["sources"] = json.loads(s.read_text(encoding="utf-8")).get("sources", {})
    return prev


def check_lists(prev, new, stats, force):
    """Жёсткие проверки (FORCE не отменяет: пустой список не бывает правильным)
    и мягкие — резкие изменения относительно прошлого сбора (FORCE=1 пропускает их осознанно)."""
    hard = []
    for key, label, minimum in (("prefixes", "подсетей", MIN_PREFIXES),
                                ("vpn_domains", "VPN-доменов", MIN_VPN_DOMAINS),
                                ("direct_domains", "no_vpn-доменов", MIN_DIRECT_DOMAINS)):
        if new[key] < minimum:
            hard.append(f"{label} {new[key]} (минимум {minimum})")

    soft = []
    a0, a1 = prev.get("addresses"), new["addresses"]
    if a0 and not (1 - MAX_SHRINK) <= a1 / a0 <= (1 + MAX_GROW):
        soft.append(f"объём адресов {a0:,} -> {a1:,} ({(a1 / a0 - 1) * 100:+.0f}%)")
    for key, label in (("vpn_domains", "VPN-доменов"), ("direct_domains", "no_vpn-доменов")):
        b0, b1 = prev.get(key), new[key]
        if b0 and b1 < b0 * (1 - MAX_SHRINK):
            soft.append(f"{label} {b0} -> {b1}")
    for src, n0 in (prev.get("sources") or {}).items():
        n1 = stats.get(src)
        if n1 is not None and n0 > 0 and n1 < n0 * SOURCE_MIN_SHARE:
            soft.append(f"{src}: префиксов {n0} -> {n1}")

    if hard:
        raise Fail("Списки подозрительно малы (FORCE это не отменяет): " + "; ".join(hard)
                   + ("\nЗаодно резкие изменения:\n  " + "\n  ".join(soft) if soft else ""))
    if not soft:
        return
    msg = "Списки изменились подозрительно сильно:\n  " + "\n  ".join(soft)
    if force:
        print(msg + "\nFORCE=1 — записываю всё равно", file=sys.stderr)
        return
    raise Fail(msg + "\nЕсли так и задумано (включил или выключил крупный сервис), запусти workflow "
                     "вручную с галочкой force или локально: FORCE=1 python collector.py")


# ---- Отчёт ------------------------------------------------------------------
def coverage(net, auto):
    """Какая доля ручной подсети уже покрыта автосбором (auto — схлопнутый, без пересечений)."""
    covered = 0
    for a in auto:
        if net.subnet_of(a):
            return 1.0
        if a.subnet_of(net):
            covered += a.num_addresses
    return covered / net.num_addresses


def manual_report(manual, auto):
    lines = ["# Ручные подсети из manual.txt", "",
             "Сколько каждой подсети уже покрывает автосбор. 100% — запись можно удалить из manual.txt, "
             "владельца для таких не ищем.", "",
             "| Подсеть | Зачем | Покрыто автосбором | Чья (AS и владелец) |", "|---|---|---|---|"]
    for net, note in manual:
        c = coverage(net, auto)
        if c >= 1:
            owner = "—"
        else:
            owner = whois(net)
            time.sleep(0.3)
        note = (note or "—").replace("|", "\\|")
        lines.append(f"| {net} | {note} | {c:.0%} | {owner} |")
    return "\n".join(lines) + "\n"


def write(path, text):
    """Через временный файл: либо старое содержимое, либо новое целиком. Всегда UTF-8 и LF."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


# ---- Главное ----------------------------------------------------------------
def main(argv=None, base=ROOT):
    argv = sys.argv[1:] if argv is None else argv
    force = os.environ.get("FORCE", "").strip().lower() in {"1", "true", "yes"}
    lists_dir, reports_dir = base / "lists", base / "reports"

    # 1. Конфигурация и ручной список — без сети
    cfg = load_config(base / "services.yaml")
    manual = read_manual(base / "manual.txt")
    vpn_domains, direct_domains = build_domains(cfg)
    if "--check" in argv:
        enabled = sum(s["enabled"] for s in cfg["services"].values())
        print(f"Конфигурация в порядке: включено сервисов {enabled}, ручных подсетей {len(manual)}, "
              f"VPN-доменов {len(vpn_domains)}, no_vpn-доменов {len(direct_domains)}")
        return

    # 2. Сбор
    auto, stats = collect(cfg)
    auto = list(ipaddress.collapse_addresses(auto))
    leftover = [n for n, _ in manual if not any(n.subnet_of(a) for a in auto)]
    print(f"manual.txt: {len(manual)} записей, из них не покрыто автосбором целиком: {len(leftover)}")
    nets = list(ipaddress.collapse_addresses(auto + leftover))

    # 3. Проверки — до любой записи на диск
    new = {"prefixes": len(nets), "addresses": sum(n.num_addresses for n in nets),
           "vpn_domains": len(vpn_domains), "direct_domains": len(direct_domains)}
    check_lists(read_previous(lists_dir, reports_dir), new, stats, force)
    report = manual_report(manual, auto)

    # 4. Запись: только данные, никаких команд — роутер сам их читает и проверяет
    lists_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    for old in (lists_dir / "vpn_ipv4.rsc", lists_dir / "dns.rsc", reports_dir / "leftover.md"):
        old.unlink(missing_ok=True)
    # /32 пишем без маски — RouterOS хранит одиночные адреса именно так
    fmt = lambda n: str(n.network_address) if n.prefixlen == 32 else str(n)
    files = {
        "vpn_ipv4.txt": [fmt(n) for n in nets],
        "domains_vpn.txt": vpn_domains,
        "domains_direct.txt": direct_domains,
    }
    for name, items in files.items():
        write(lists_dir / name, "".join(f"{x}\n" for x in items))
    # Версия списков: роутер обновляется только когда она меняется
    h = hashlib.sha256(b"".join((lists_dir / n).read_bytes() for n in files)).hexdigest()
    write(lists_dir / "version.txt", h + "\n")
    write(reports_dir / "stats.json",
          json.dumps({"sources": stats, **new}, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    write(reports_dir / "manual.md", report)

    print(f"Готово: {len(nets)} префиксов ({new['addresses']:,} адресов), "
          f"{len(vpn_domains)} VPN-доменов, {len(direct_domains)} no_vpn")


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # консоль Windows не падает на незнакомых символах
    try:
        main()
    except Fail as e:
        if os.environ.get("GITHUB_ACTIONS"):
            print("::error::" + str(e).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))
        sys.exit(f"ОШИБКА: {e}\nНичего не записано.")
