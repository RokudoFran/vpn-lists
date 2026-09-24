#!/usr/bin/env python3
"""Собирает IP-префиксы и домены по services.yaml + manual.txt в простые текстовые списки."""
import hashlib, ipaddress, json, pathlib, sys, time, urllib.request
import yaml

MIN_PREFIXES = 50        # защита: если собралось меньше — ничего не коммитим
RIPE_ASN = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"
RIPE_WHO = "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"

def get(url, as_json=True):
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpn-lists-collector"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read().decode()
            return json.loads(data) if as_json else data
        except Exception as e:
            print(f"{url}: попытка {attempt+1} не удалась: {e}", file=sys.stderr)
            time.sleep(5)
    sys.exit(f"Не удалось получить {url}, выхожу без изменений")

# Официальные списки IP от самих компаний
SOURCES = {
    "cloudflare": lambda: get("https://www.cloudflare.com/ips-v4", as_json=False).split(),
    "cloudfront": lambda: [p["ip_prefix"] for p in get("https://ip-ranges.amazonaws.com/ip-ranges.json")["prefixes"]
                           if p["service"] == "CLOUDFRONT"],
    "fastly":     lambda: get("https://api.fastly.com/public-ip-list")["addresses"],
}

def asn_prefixes(asn):
    return [p["prefix"] for p in get(RIPE_ASN.format(asn))["data"]["prefixes"]]

def v4(items):
    out = []
    for p in items:
        try:
            n = ipaddress.ip_network(p.strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.is_global:
            out.append(n)
    return out

def whois(net):
    try:
        d = get(RIPE_WHO.format(net))["data"]
        asns = d.get("asns") or []
        if asns:
            return ", ".join(f"AS{a['asn']} {a['holder']}" for a in asns)
        return "не анонсируется (никто не маршрутизирует)"
    except SystemExit:
        return "не удалось узнать"

def main():
    cfg = yaml.safe_load(open("services.yaml", encoding="utf-8"))
    auto, vpn_domains = [], []
    for name, s in cfg["services"].items():
        if not s.get("enabled"):
            continue
        for asn in s.get("asn") or []:
            got = v4(asn_prefixes(asn))
            print(f"{name}: AS{asn} -> {len(got)} префиксов")
            auto += got
        for src in s.get("sources") or []:
            got = v4(SOURCES[src]())
            print(f"{name}: {src} -> {len(got)} префиксов")
            auto += got
        vpn_domains += s.get("domains") or []
    auto = list(ipaddress.collapse_addresses(auto))

    # Ручные подсети: берём только то, что автосбор не покрывает
    manual_file = pathlib.Path("manual.txt")
    manual = v4(l.split("#")[0] for l in manual_file.read_text().splitlines()) if manual_file.exists() else []
    leftover = [n for n in manual if not any(n.subnet_of(a) for a in auto)]
    print(f"manual.txt: {len(manual)} записей, из них не покрыто автосбором: {len(leftover)}")

    nets = list(ipaddress.collapse_addresses(auto + leftover))
    if len(nets) < MIN_PREFIXES:
        sys.exit(f"Подозрительно мало префиксов ({len(nets)}), выхожу без изменений")
    vpn_domains = sorted(set(vpn_domains))
    direct_domains = sorted(set((cfg.get("no_vpn") or {}).get("domains") or []))

    # Только данные, никаких команд: роутер сам их читает и проверяет
    out = pathlib.Path("lists"); out.mkdir(exist_ok=True)
    for old in ("vpn_ipv4.rsc", "dns.rsc"):
        (out / old).unlink(missing_ok=True)
    # /32 пишем без маски — RouterOS хранит одиночные адреса именно так
    fmt = lambda n: str(n.network_address) if n.prefixlen == 32 else str(n)
    files = {
        "vpn_ipv4.txt": [fmt(n) for n in nets],
        "domains_vpn.txt": vpn_domains,
        "domains_direct.txt": direct_domains,
    }
    for name, items in files.items():
        (out / name).write_text("".join(f"{x}\n" for x in items))

    # Версия списков: роутер обновляется только когда она меняется
    h = hashlib.sha256(b"".join((out / n).read_bytes() for n in files)).hexdigest()
    (out / "version.txt").write_text(h + "\n")

    # Отчёт: чьи подсети остались непонятными в manual.txt
    rep = pathlib.Path("reports"); rep.mkdir(exist_ok=True)
    lines = ["# Подсети из manual.txt, которые не покрыты автосбором", "",
             f"Всего: {len(leftover)}", "", "| Подсеть | Чья (AS и владелец) |", "|---|---|"]
    for n in leftover:
        lines.append(f"| {n} | {whois(n)} |")
        time.sleep(0.3)
    (rep / "leftover.md").write_text("\n".join(lines) + "\n")

    print(f"Готово: {len(nets)} префиксов, {len(vpn_domains)} VPN-доменов, {len(direct_domains)} no_vpn")

if __name__ == "__main__":
    main()
