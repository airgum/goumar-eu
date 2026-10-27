import unittest

from support import Base, Env
import config
import scrub


class ScrubTests(Base):
    def setUp(self):
        super().setUp()
        import os
        self._old = {k: os.environ.get(k) for k in self.e.env}
        os.environ.update(self.e.env)
        self.addCleanup(self.restore)
        self.lists = config.load_lists()

    def restore(self):
        import os
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def s(self, text):
        return scrub.scrub_text(text, self.lists)

    def test_names_replaced_with_stable_letters(self):
        out = self.s("Wrote to Zebrov, then Quorvex, then Зеброва again.")
        self.assertNotIn("Zebrov", out)
        self.assertNotIn("Зеброва", out)
        self.assertNotIn("Quorvex", out)
        self.assertEqual(out.count("[name A]"), 2)
        self.assertIn("[name B]", out)

    def test_case_endings(self):
        for form in ("Зебровым", "Зеброва", "ЗЕБРОВ"):
            self.assertIn("[name", self.s("Привет, " + form), form)

    def test_multiword_name_longest_match(self):
        out = self.s("Quorvex Lumina Sur wrote")
        self.assertEqual(out, "[name A] wrote")

    def test_nick_with_separators(self):
        self.assertNotIn("zebrov", self.s("user zebrov_fan said").lower())

    def test_tme_and_hosts(self):
        out = self.s("see t.me/somechan and https://example.com/x/y and t.me/airgum and "
                     "https://goumar.eu/a https://commintator.goumar.eu https://github.com/airgum/repo "
                     "https://github.com/other/repo instagram.com/commintator.app instagram.com/other")
        self.assertIn("[channel A]", out)
        self.assertNotIn("somechan", out)
        self.assertNotIn("example.com", out)
        self.assertIn("t.me/airgum", out)
        self.assertIn("https://goumar.eu/a", out)
        self.assertIn("https://commintator.goumar.eu", out)
        self.assertIn("https://github.com/airgum/repo", out)
        self.assertNotIn("github.com/other", out)
        self.assertIn("instagram.com/commintator.app", out)
        self.assertNotIn("instagram.com/other", out)

    def test_same_channel_same_letter(self):
        out = self.s("t.me/aaa then t.me/bbb then https://t.me/aaa")
        self.assertEqual(out.count("[channel A]"), 2)
        self.assertEqual(out.count("[channel B]"), 1)

    def test_deny_phrases_removed(self):
        out = self.s("Plumbo Industries and BlorpSpy and поставщика Фиктивного")
        self.assertEqual(out.count("[removed]"), 3)

    def test_whitelist_not_scrubbed(self):
        out = self.s("Granada, Spain and Sierra Nevada, plus Zebrov")
        self.assertIn("Granada, Spain", out)
        self.assertIn("Sierra Nevada", out)
        self.assertIn("[name A]", out)

    def test_clean_text_unchanged(self):
        t = "A perfectly ordinary sentence about gardens."
        self.assertEqual(self.s(t), t)

    def test_handles_and_emails(self):
        out = self.s("cc @clientchan, @Clientchan and @other; @airgum @commintator_bot ok; "
                     "write a@b.example, A@B.example and me@goumar.eu")
        self.assertEqual(out.count("[handle A]"), 2)
        self.assertIn("[handle B]", out)
        self.assertIn("@airgum @commintator_bot", out)
        self.assertEqual(out.count("[email A]"), 2)
        self.assertIn("me@goumar.eu", out)
        self.assertNotIn("clientchan", out.lower())
        self.assertNotIn("b.example", out)

    def test_handle_wins_over_name_inside_it(self):
        self.assertEqual(self.s("@zebrov_fan"), "[handle A]")

    def test_variants_scrubbed(self):
        self.assertIn("[name", self.s("Zebbrovs"))

    def test_server_details(self):
        out = self.s("db dbhost:5432 at 10.20.30.40 and 2001:db8::1, logs in /var/log/app.log and /Users/x/y.txt "
                     "again dbhost:5432 ok")
        self.assertEqual(out.count("[host A]"), 2)
        self.assertIn("[ip A]", out)
        self.assertIn("[ip B]", out)
        self.assertEqual(out.count("[path"), 2)
        self.assertNotIn("/log", out)
        self.assertNotIn("y.txt", out)

    def test_mixed_sample_passes_hook_with_zero_findings(self):
        raw = ("Zebrov (@clientchan, zz@example.org) wrote from t.me/somechan about Plumbo Industries, "
               "see https://example.com/q. Server dbhost:5432 / api.internal.net:8080/x at 10.20.30.40 and "
               "2001:db8::1; files /Users/x/a.txt, /etc/hosts, /opt/app, /var/log, /home/me. "
               "Call %s. Quorvex Lumina Sur and Зеброва too. Granada, Spain stays." % "+34 600 111 222")
        out = self.e.run("scrub.py", stdin=raw).stdout
        p = self.e.write("mixed.md", out)
        r = self.e.run("hook.py", [str(p)])
        self.assertEqual((r.returncode, r.stdout), (0, ""), out)

    def test_scrubbed_output_passes_the_hook(self):
        raw = "Zebrov wrote from t.me/somechan about Plumbo Industries, see https://example.com/q"
        out = self.e.run("scrub.py", stdin=raw).stdout
        p = self.e.write("clean.md", out)
        r = self.e.run("hook.py", [str(p)])
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_cli_canary_failure_exits_nonzero_before_output(self):
        bad = Env(with_canary=False)
        self.addCleanup(bad.close)
        r = bad.run("scrub.py", stdin="Zebrov")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_cli_ok_prints_version_and_text(self):
        r = self.e.run("scrub.py", stdin="Hello Zebrov")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "Hello [name A]")
        self.assertIn(self.e.version, r.stderr)

    def test_cli_fail_closed_inputs(self):
        for key in ("GOUMAR_DENYLIST_FILE", "GOUMAR_NAMES_HASHES_FILE", "GOUMAR_SALT_FILE", "GOUMAR_VERSION_FILE"):
            r = self.e.run("scrub.py", stdin="x", env_override={key: str(self.e.dir / "missing")})
            self.assertEqual(r.returncode, 2, key)
            self.assertEqual(r.stdout, "", key)


if __name__ == "__main__":
    unittest.main()
