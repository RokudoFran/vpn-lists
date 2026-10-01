"""Офлайн-тесты collector.py: сеть подменена, проверяем защиту от поломок.

    python -m unittest discover -s tests -v
"""
import contextlib, hashlib, io, ipaddress, json, os, pathlib, sys, tempfile, textwrap, unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import collector  # noqa: E402

VPN_DOMAINS = [f"svc{i}.com" for i in range(1, 23)]          # 22 >= MIN_VPN_DOMAINS
DIRECT_DOMAINS = ["bank.ru", "gov.ru", "shop.ru", "maps.ru", "taxi.ru", "mail.ru"]
ASN_NETS = [f"45.{i}.1.0/24" for i in range(1, 61)]          # 60 префиксов от AS64500
CF_NETS = [f"104.{i}.0.0/16" for i in range(16, 96, 2)]      # 40 несмежных префиксов от «cloudflare»


def services_yaml(vpn=VPN_DOMAINS, direct=DIRECT_DOMAINS, extra=""):
    return textwrap.dedent(f"""\
        services:
          alpha:
            enabled: true
            asn: [64500]
            domains: [{", ".join(vpn)}]
          beta:
            enabled: true
            asn: []
            sources: [cloudflare]
            domains: []
          off:
            enabled: false
            asn: [64511]
            prefixes: [45.200.0.0/22]
            domains: [off.com]
        {extra}
        no_vpn:
          domains: [{", ".join(direct)}]
        """)


class Repo:
    """Временная копия репозитория с подменённой сетью."""

    def __init__(self, yaml_text=None, manual="# AWS\n3.251.50.149/32\n# CDN\n130.176.0.0/16  # какой-то CDN\n"):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        (self.base / "services.yaml").write_text(yaml_text or services_yaml(), encoding="utf-8")
        (self.base / "manual.txt").write_text(manual, encoding="utf-8")
        self.asn = {64500: list(ASN_NETS), 64511: ["45.201.0.0/22"]}
        self.cf = list(CF_NETS)
        self.dns = {}                                        # домен -> ответ DoH, по умолчанию ok

    def run(self, *args, force=False):
        env = {"FORCE": "1"} if force else {}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(collector, "asn_prefixes", lambda asn: self.asn[asn]), \
             mock.patch.dict(collector.SOURCES, {"cloudflare": lambda: self.cf}), \
             mock.patch.object(collector, "whois", lambda net: "AS0 TEST"), \
             mock.patch.object(collector, "domain_status", lambda d: self.dns.get(d, "ok")), \
             mock.patch.object(collector.time, "sleep", lambda s: None), \
             mock.patch.dict(os.environ, env, clear=False), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if not force:
                os.environ.pop("FORCE", None)
            collector.main(list(args), base=self.base)
        return out.getvalue() + err.getvalue()

    def read(self, rel):
        return (self.base / rel).read_text(encoding="utf-8")

    def snapshot(self):
        return {p.relative_to(self.base).as_posix(): p.read_bytes()
                for p in sorted(self.base.rglob("*")) if p.is_file()}

    def close(self):
        self.tmp.cleanup()


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def assertFailsAndWritesNothing(self, *args, msg=None, force=False):
        before = self.repo.snapshot()
        with self.assertRaises(collector.Fail) as cm:
            self.repo.run(*args, force=force)
        self.assertEqual(before, self.repo.snapshot(), "при ошибке ничего не должно записываться")
        if msg:
            self.assertIn(msg, str(cm.exception))
        return cm.exception

    # --- реальный конфиг репозитория ---
    def test_repo_config_is_valid(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            collector.main(["--check"], base=ROOT)
        self.assertIn("Конфигурация в порядке", out.getvalue())

    # --- нормальный прогон ---
    def test_happy_path(self):
        self.repo.run()
        nets = self.repo.read("lists/vpn_ipv4.txt").split()
        self.assertIn("3.251.50.149", nets, "/32 пишется без маски")
        self.assertIn("130.176.0.0/16", nets)
        self.assertNotIn("45.200.0.0/22", nets, "выключенный сервис не собирается")
        self.assertEqual(self.repo.read("lists/domains_vpn.txt").split(), sorted(VPN_DOMAINS))
        files = ["vpn_ipv4.txt", "domains_vpn.txt", "domains_direct.txt"]
        h = hashlib.sha256(b"".join((self.repo.base / "lists" / f).read_bytes() for f in files)).hexdigest()
        self.assertEqual(self.repo.read("lists/version.txt").strip(), h)
        stats = json.loads(self.repo.read("reports/stats.json"))
        self.assertEqual(stats["sources"], {"alpha:AS64500": 60, "beta:cloudflare": 40})
        raw = (self.repo.base / "reports/manual.md").read_bytes()
        self.assertNotIn(b"\r\n", raw)
        self.assertIn("какой-то CDN", raw.decode("utf-8"))

    def test_second_identical_run_changes_nothing(self):
        self.repo.run()
        before = self.repo.snapshot()
        self.repo.run()
        self.assertEqual(before, self.repo.snapshot())

    # --- опечатки в ручных записях ---
    def test_mask_typo_in_manual_stops(self):
        (self.repo.base / "manual.txt").write_text("185.135.84.0/2\n", encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="host bits set")

    def test_garbage_in_manual_stops(self):
        (self.repo.base / "manual.txt").write_text("45.135.120.0\\22\n", encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="manual.txt:1")

    def test_too_wide_manual_entry_stops(self):
        (self.repo.base / "manual.txt").write_text("45.0.0.0/8\n", encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="шире /12")

    def test_duplicate_manual_entry_stops(self):
        (self.repo.base / "manual.txt").write_text("8.6.112.0/24\n8.6.112.0/24\n", encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="уже есть выше")

    # --- опечатки в services.yaml ---
    def test_unknown_service_key_stops(self):
        bad = services_yaml().replace("domains: [off.com]", "domain: [off.com]")
        (self.repo.base / "services.yaml").write_text(bad, encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="неизвестные ключи")

    def test_misspelled_no_vpn_section_stops(self):
        bad = services_yaml().replace("no_vpn:", "no-vpn:")
        (self.repo.base / "services.yaml").write_text(bad, encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="неизвестные разделы")

    def test_missing_enabled_stops(self):
        bad = services_yaml().replace("    enabled: false\n", "")
        (self.repo.base / "services.yaml").write_text(bad, encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="enabled")

    def test_bad_prefix_in_disabled_service_still_stops(self):
        bad = services_yaml().replace("45.200.0.0/22", "45.200.0.0/2")
        (self.repo.base / "services.yaml").write_text(bad, encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="host bits set")

    def test_domains_are_normalized_and_validated(self):
        self.assertEqual(collector.norm_domain(" Example.COM. ", "t"), "example.com")
        for bad in ("bad_domain.com", "госуслуги.рф", "nodot", "a..b.com", "-x.com"):
            with self.assertRaises(collector.Fail, msg=bad):
                collector.norm_domain(bad, "t")

    def test_nested_domains_are_dropped(self):
        yaml_text = services_yaml(vpn=VPN_DOMAINS + ["gemini.svc1.com"],
                                  direct=DIRECT_DOMAINS + ["online.bank.ru"])
        (self.repo.base / "services.yaml").write_text(yaml_text, encoding="utf-8")
        self.repo.run()
        self.assertNotIn("gemini.svc1.com", self.repo.read("lists/domains_vpn.txt").split())
        self.assertNotIn("online.bank.ru", self.repo.read("lists/domains_direct.txt").split())

    def test_domain_in_both_lists_stops(self):
        yaml_text = services_yaml(direct=DIRECT_DOMAINS + ["api.svc1.com"])
        (self.repo.base / "services.yaml").write_text(yaml_text, encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="api.svc1.com")

    # --- защита от сбоев источников ---
    def test_source_returning_too_wide_prefix_stops(self):
        self.repo.asn[64500] = ASN_NETS + ["128.0.0.0/2"]
        self.assertFailsAndWritesNothing(msg="шире /8")

    def test_vanished_source_stops_and_force_overrides(self):
        self.repo.run()
        self.repo.asn[64500] = ASN_NETS[:25]           # AS «похудела» с 60 до 25 префиксов
        self.assertFailsAndWritesNothing(msg="alpha:AS64500: префиксов 60 -> 25")
        self.repo.run(force=True)
        self.assertEqual(json.loads(self.repo.read("reports/stats.json"))["sources"]["alpha:AS64500"], 25)

    def test_volume_jump_stops(self):
        self.repo.run()
        self.repo.cf = CF_NETS + ["23.32.0.0/11"]      # +2 млн адресов разом
        self.assertFailsAndWritesNothing(msg="объём адресов")

    def test_too_few_direct_domains_stop_even_with_force(self):
        (self.repo.base / "services.yaml").write_text(services_yaml(direct=["bank.ru"]), encoding="utf-8")
        self.assertFailsAndWritesNothing(msg="no_vpn-доменов 1", force=True)

    def test_domains_shrink_stops(self):
        many_vpn = [f"s{i}.com" for i in range(40)]
        many_direct = [f"d{i}.ru" for i in range(10)]
        write = lambda **kw: (self.repo.base / "services.yaml").write_text(services_yaml(**kw), encoding="utf-8")
        write(vpn=many_vpn, direct=many_direct)
        self.repo.run()
        write(vpn=many_vpn[:32], direct=many_direct)           # 40 -> 32: -20%, норма
        self.repo.run()
        write(vpn=many_vpn[:22], direct=many_direct)           # 32 -> 22: -31%, стоп
        self.assertFailsAndWritesNothing(msg="VPN-доменов 32 -> 22")
        write(vpn=many_vpn[:32], direct=many_direct[:7])       # 10 -> 7 direct: -30%, стоп
        self.assertFailsAndWritesNothing(msg="no_vpn-доменов 10 -> 7")

    def test_hard_and_soft_problems_reported_together(self):
        self.repo.run()
        self.repo.asn[64500] = []                              # AS пропала целиком
        self.repo.cf = CF_NETS[:10]
        err = self.assertFailsAndWritesNothing(msg="подсетей", force=True)
        self.assertIn("alpha:AS64500: префиксов 60 -> 0", str(err))

    # --- отчёт ---
    def test_report_shows_partial_and_full_coverage(self):
        manual = "# половина\n45.61.0.0/16\n# целиком внутри AS\n45.5.1.0/24\n"
        (self.repo.base / "manual.txt").write_text(manual, encoding="utf-8")
        self.repo.asn[64500] = ASN_NETS + ["45.61.0.0/17"]
        self.repo.run()
        report = self.repo.read("reports/manual.md")
        self.assertIn("| 45.61.0.0/16 | половина | 50% | AS0 TEST |", report)
        self.assertIn("| 45.5.1.0/24 | целиком внутри AS | 100% | — |", report)
        self.assertFalse((self.repo.base / "reports/leftover.md").exists())

    def test_sources_report_and_volumes(self):
        self.repo.run()
        stats = json.loads(self.repo.read("reports/stats.json"))
        self.assertEqual(stats["addresses_by_source"], {"alpha:AS64500": 60 * 256, "beta:cloudflare": 40 * 65536})
        rows = [l for l in self.repo.read("reports/sources.md").splitlines() if l.startswith("| ")][1:]
        self.assertTrue(rows[0].startswith("| beta:cloudflare | 40 | 2 621 440 |"), rows[0])
        self.assertTrue(rows[1].startswith("| alpha:AS64500 | 60 | 15 360 |"), rows[1])
        self.assertIn("manual.txt (не покрыто автосбором)", rows[2])
        self.assertTrue(rows[-1].startswith("| **Итого в vpn_ipv4.txt** |"))

    def test_volume_overlap_inside_source_is_not_double_counted(self):
        self.repo.asn[64500] = ASN_NETS + ["45.1.1.0/25"]     # кусок уже анонсированной /24
        self.repo.run()
        stats = json.loads(self.repo.read("reports/stats.json"))
        self.assertEqual(stats["sources"]["alpha:AS64500"], 61)
        self.assertEqual(stats["addresses_by_source"]["alpha:AS64500"], 60 * 256)

    def test_dead_domain_is_reported_but_build_continues(self):
        self.repo.dns = {"svc3.com": "nxdomain", "bank.ru": "servfail"}
        out = self.repo.run()
        report = self.repo.read("reports/domains.md")
        self.assertIn("| svc3.com | VPN | не существует (NXDOMAIN) |", report)
        self.assertIn("| bank.ru | no_vpn | ошибка DNS (SERVFAIL) |", report)
        self.assertIn("проблемных 2", report)
        self.assertIn("svc3.com", self.repo.read("lists/domains_vpn.txt"), "отчёт не меняет списки")
        self.assertIn("ВНИМАНИЕ: домен svc3.com", out)

    def test_doh_outage_is_not_reported_as_dead_domains(self):
        self.repo.dns = {d: "error" for d in VPN_DOMAINS + DIRECT_DOMAINS}
        self.repo.run()
        report = self.repo.read("reports/domains.md")
        self.assertIn("Проверка не удалась", report)
        self.assertNotIn("| svc1.com |", report)

    def test_all_domains_fine(self):
        self.repo.run()
        self.assertIn(f"Проверено {len(VPN_DOMAINS) + len(DIRECT_DOMAINS)}, проблемных 0.",
                      self.repo.read("reports/domains.md"))

    def test_check_mode_needs_no_network(self):
        with mock.patch.object(collector, "get", side_effect=AssertionError("сеть в --check")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                collector.main(["--check"], base=self.repo.base)
        self.assertIn("Конфигурация в порядке", out.getvalue())


if __name__ == "__main__":
    unittest.main()
