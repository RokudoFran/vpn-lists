#!/usr/bin/env python3
"""Собирает IP-префиксы по services.yaml + manual.txt и готовит .rsc для MikroTik."""
import hashlib, ipaddress, json, pathlib, sys, time, urllib.request
import yaml

VPN_DNS = "8.8.8.8"      # DNS для заблокированных доменов (сам идёт через туннель)
DIRECT_DNS = "77.88.8.8" # DNS для no_vpn доменов (напрямую)
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

    out = pathlib.Path("lists"); out.mkdir(exist_ok=True)
    (out / "vpn_ipv4.txt").write_text("".join(f"{n}\n" for n in nets))
    al = ["/ip firewall address-list remove [find list=vpn_only comment=git]"]
    al += [f":do {{/ip firewall address-list add list=vpn_only comment=git address={n}}} on-error={{}}"
           for n in nets]
    (out / "vpn_ipv4.rsc").write_text("\n".join(al) + "\n")

    dns = ["/ip dns static remove [find comment=git-dns]"]
    for d in vpn_domains:
        dns.append(f":do {{/ip dns static add name={d} type=FWD forward-to={VPN_DNS} "
                   f"match-subdomain=yes address-list=vpn_only comment=git-dns}} on-error={{}}")
    for d in direct_domains:
        dns.append(f":do {{/ip dns static add name={d} type=FWD forward-to={DIRECT_DNS} "
                   f"match-subdomain=yes address-list=no_vpn comment=git-dns}} on-error={{}}")
    (out / "dns.rsc").write_text("\n".join(dns) + "\n")

    # Версия списков: роутер импортирует только когда она меняется
    h = hashlib.sha256((out / "vpn_ipv4.rsc").read_bytes() + (out / "dns.rsc").read_bytes()).hexdigest()
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
