#!/usr/bin/env python3
"""Собирает IP-префиксы по services.yaml и готовит .rsc для MikroTik."""
import ipaddress, json, pathlib, sys, time, urllib.request
import yaml

VPN_DNS = "8.8.8.8"      # DNS для заблокированных доменов (сам идёт через туннель)
DIRECT_DNS = "77.88.8.8" # DNS для no_vpn доменов (напрямую)
MIN_PREFIXES = 50        # защита: если собралось меньше — ничего не коммитим
RIPE = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"

def prefixes(asn):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(RIPE.format(asn), timeout=60) as r:
                data = json.load(r)
            return [p["prefix"] for p in data["data"]["prefixes"]]
        except Exception as e:
            print(f"AS{asn}: попытка {attempt+1} не удалась: {e}", file=sys.stderr)
            time.sleep(5)
    sys.exit(f"AS{asn}: не удалось получить префиксы, выхожу без изменений")

def main():
    cfg = yaml.safe_load(open("services.yaml", encoding="utf-8"))
    nets, vpn_domains = [], []
    for name, s in cfg["services"].items():
        if not s.get("enabled"):
            continue
        for asn in s.get("asn") or []:
            v4 = [n for n in map(ipaddress.ip_network, prefixes(asn))
                  if n.version == 4 and n.is_global]
            print(f"{name}: AS{asn} -> {len(v4)} префиксов")
            nets += v4
        vpn_domains += s.get("domains") or []

    nets = list(ipaddress.collapse_addresses(nets))
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

    print(f"Готово: {len(nets)} префиксов, {len(vpn_domains)} VPN-доменов, {len(direct_domains)} no_vpn")

if __name__ == "__main__":
    main()
