import os
import shutil
import subprocess
import unittest

from support import Base, Env, FAKE_PHONE
import config
import detect


def rules(out):
    return [l.split("\t")[2] for l in out.splitlines() if l.count("\t") == 2]


class RuleTests(Base):
    """Every pattern rule, through the CLI on a .md file."""

    def scan(self, text, name="a.md"):
        p = self.e.write(name, text)
        return self.e.run("hook.py", [str(p)])

    def assertRule(self, text, rule, name="a.md"):
        r = self.scan(text, name)
        self.assertEqual(r.returncode, 1, (text, r.stdout, r.stderr))
        self.assertIn(rule, rules(r.stdout), text)

    def assertClean(self, text, name="a.md"):
        r = self.scan(text, name)
        self.assertEqual(r.returncode, 0, (text, r.stdout, r.stderr))

    def test_static_phrase_variants(self):
        self.assertRule("We met Plumbo Industries.", "deny-phrase")
        self.assertRule("PLUMBOINDUSTRIES", "deny-phrase")
        self.assertRule("Blorp Spy", "deny-phrase")
        self.assertRule("blorpspy", "deny-phrase")

    def test_cyrillic_stem_matching(self):
        self.assertRule("у поставщика Фиктивного", "deny-phrase")
        self.assertRule("поставщиком фиктивным", "deny-phrase")

    def test_hashed_names_and_ngrams(self):
        self.assertRule("hello Зеброва", "hash-name")
        self.assertRule("by Quorvex Lumina Sur today", "hash-name")
        self.assertRule("nick @zebrov_fan", "hash-name")

    def test_ip(self):
        self.assertRule("server 10.20.30.40 up", "ipv4")
        self.assertRule("v6 2001:db8::1 here", "ipv6")
        self.assertClean("version 1.2.3 and time 12:30:45 and 999.1.1.1")

    def test_user_at_host_and_email(self):
        self.assertRule("ssh deploy@prodbox now", "user-at-host")
        self.assertRule("mail someone@example.org", "email")
        self.assertClean("write to me@goumar.eu")

    def test_abs_paths_roots_only(self):
        self.assertRule("see /Users/x/file", "abs-path")
        self.assertRule("see /etc/hosts", "abs-path")
        self.assertRule("in /opt, /var and /home", "abs-path")
        self.assertClean("a url https://goumar.eu/var/page and and/or /optional")

    def test_host_port(self):
        self.assertRule("db at dbhost:5432", "host-port")
        self.assertRule("try api.internal.net:8080/x", "host-port")
        self.assertClean("ratio 3:30 and note:text and 10:99999999")

    def test_keys(self):
        self.assertRule("key sk-abcdefghijklmnop1234", "secret-key")
        self.assertRule("tok ghp_abcdefghijklmnopqrstuv", "secret-key")
        self.assertClean("a task-based approach sk-short")

    def test_phone_any_formatting(self):
        for fmt in ("+34 600 111 222", "0034-600-111-222", "34600111222", "(600) 111.222", "600111222"):
            self.assertRule("call %s now" % fmt, "phone")
        self.assertClean("call +34 700 111 222 now")

    def test_phone_digits_come_from_denylist_not_code(self):
        other = Env(deny="Plumbo Industries\nphone: +1 555 000 9999\n")
        self.addCleanup(other.close)
        p = other.write("a.md", "call %s and +1 (555) 000-9999" % FAKE_PHONE)
        r = other.run("hook.py", [str(p)])
        self.assertEqual(rules(r.stdout), ["phone"])

    def test_any_other_email_flagged_owner_not(self):
        self.assertClean("me@goumar.eu, ME@GOUMAR.EU")
        self.assertRule("x@commintator.app.evil.com", "email")

    def test_whitelist_precedence(self):
        env = Env(names=["Sierra Nevada Granada", "Zebrov"])
        self.addCleanup(env.close)
        p = env.write("a.md", "Granada, Spain; Гранада, Испания; Granada, España; Sierra Nevada; "
                              "Сьерра-Невада; @commintator.app; airgum; me@goumar.eu")
        r = env.run("hook.py", [str(p)])
        self.assertEqual(r.returncode, 0, r.stdout)
        p = env.write("b.md", "Sierra Nevada Zebrov")
        r = env.run("hook.py", [str(p)])
        self.assertEqual(rules(r.stdout), ["hash-name"])

    def test_whitelist_matches_whole_phrase_only(self):
        self.assertRule("x@commintator.app.evil.com", "email")
        self.assertRule("mail me@goumar.eu.evil.com", "email")
        env = Env(names=["airgumx"])
        self.addCleanup(env.close)
        p = env.write("a.md", "airgumx and airgum")
        self.assertEqual(rules(env.run("hook.py", [str(p)]).stdout), ["hash-name"])

    def test_at_handle(self):
        self.assertRule("ping @clientchan please", "at-handle")
        self.assertRule("ping @Client_Chan2", "at-handle")
        self.assertClean("by @airgum, @AIRGUM, @commintator, @commintator_bot, @commintator.app, me@goumar.eu")
        self.assertClean("npm @scope/pkg and @ab and mail-free text")
        self.assertRule("mail zz@example.org", "email")
        self.assertEqual(rules(self.scan("mail zz@example.org").stdout), ["email"])  # not also a handle

    def test_variant_folding_in_hook(self):
        self.assertRule("hello Tzebrov and Zebbrovs", "hash-name")

    def test_offset_is_byte_offset(self):
        p = self.e.write("a.md", "ёё 10.20.30.40")
        r = self.e.run("hook.py", [str(p)])
        self.assertEqual(r.stdout.split("\t")[1], "5")

    def test_json_and_txt(self):
        self.assertRule('{"k": "Zebrov"}', "hash-name", "a.json")
        self.assertRule("Zebrov", "hash-name", "a.txt")

    def test_other_extensions_ignored(self):
        self.assertClean("Zebrov 10.20.30.40", "a.py")


class HtmlTests(Base):
    def scan(self, html):
        p = self.e.write("p.html", html)
        return self.e.run("hook.py", [str(p)])

    def test_visible_text_alt_title_meta_scanned(self):
        for html in ("<p>Hi Zebrov</p>", '<img alt="Zebrov">', '<a title="Zebrov">x</a>',
                     '<meta name="description" content="Zebrov">', "<title>Zebrov</title>"):
            r = self.scan(html)
            self.assertEqual(rules(r.stdout), ["hash-name"], html)

    def test_css_js_svg_and_other_attrs_ignored(self):
        html = ('<style>.a{background:url(/var/x)} /* Zebrov */</style><script>var x="10.20.30.40 Zebrov"</script>'
                '<svg><text>Zebrov</text></svg><a href="/home/x" class="Zebrov">ok</a><p>fine</p>')
        r = self.scan(html)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_name_split_across_inline_tags_in_one_text_node(self):
        r = self.scan("<p>Quorvex Lumina Sur</p>")
        self.assertIn("hash-name", rules(r.stdout))

    def test_offset_points_into_source(self):
        src = "<html><body><p>pad pad Zebrov</p></body></html>"
        r = self.scan(src)
        off = int(r.stdout.split("\t")[1])
        self.assertLessEqual(abs(off - src.index("Zebrov")), 1)


class PdfTests(Base):
    def test_pdf_without_pdftotext_fails_closed(self):
        p = self.e.write("a.pdf", b"%PDF-1.4 fake", mode="wb")
        r = self.e.run("hook.py", [str(p)], env_override={"PATH": "/nonexistent"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("pdftotext", r.stderr)

    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext not installed")
    def test_pdf_text_scanned(self):
        pdf = (b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
               b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
               b"4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 20 100 Td (Zebrov) Tj ET\nendstream endobj\n"
               b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R>>\n")
        p = self.e.write("a.pdf", pdf, mode="wb")
        r = self.e.run("hook.py", [str(p)])
        self.assertEqual(rules(r.stdout), ["hash-name"])


class FailClosedTests(Base):
    def run_hook(self, **kw):
        p = self.e.write("ok.md", "nothing here")
        return self.e.run("hook.py", [str(p)], **kw)

    def test_clean_file_passes(self):
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("version=" + self.e.version, r.stderr)

    def test_each_missing_input_stops(self):
        for key in ("GOUMAR_DENYLIST_FILE", "GOUMAR_NAMES_HASHES_FILE", "GOUMAR_SALT_FILE", "GOUMAR_VERSION_FILE"):
            r = self.run_hook(env_override={key: str(self.e.dir / "missing")})
            self.assertEqual(r.returncode, 2, key)

    def test_empty_inputs_stop(self):
        for name in ("denylist.txt", "names.hashes", "salt"):
            env = Env()
            self.addCleanup(env.close)
            (env.dir / name).write_text("")
            p = env.write("ok.md", "x")
            self.assertEqual(env.run("hook.py", [str(p)]).returncode, 2, name)

    def test_malformed_hash_line_stops(self):
        (self.e.dir / "names.hashes").write_text("not-a-hash\n")
        self.assertEqual(self.run_hook().returncode, 2)

    def test_version_mismatch_stops(self):
        (self.e.dir / "denylist.version").write_text("deadbeef0000\n")
        r = self.run_hook()
        self.assertEqual(r.returncode, 2)
        self.assertIn("version mismatch", r.stderr)

    def test_changed_denylist_changes_version(self):
        (self.e.dir / "denylist.txt").write_text(self.e.dir.joinpath("denylist.txt").read_text() + "Extra Phrase\n")
        self.assertEqual(self.run_hook().returncode, 2)

    def test_print_version_matches_and_works_without_version_file(self):
        r = self.e.run("hook.py", ["--print-version"], env_override={"GOUMAR_VERSION_FILE": str(self.e.dir / "none")})
        self.assertEqual(r.stdout.strip(), self.e.version)

    def test_canary_missing_stops(self):
        bad = Env(with_canary=False)
        self.addCleanup(bad.close)
        p = bad.write("ok.md", "x")
        r = bad.run("hook.py", [str(p)])
        self.assertEqual(r.returncode, 2)
        self.assertIn("canary", r.stderr)

    def test_hashes_from_split_secrets(self):
        text = (self.e.dir / "names.hashes").read_text().split()
        mid = len(text) // 2
        env = {"GOUMAR_NAMES_HASHES_1": "\n".join(text[:mid]), "GOUMAR_NAMES_HASHES_2": "\n".join(text[mid:])}
        p = self.e.write("a.md", "Зеброва")
        r = self.e.run("hook.py", [str(p)], env_override=env, drop=("GOUMAR_NAMES_HASHES_FILE",))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("version=" + self.e.version, r.stderr)

    def test_content_env_for_denylist_and_salt(self):
        env = {"GOUMAR_DENYLIST": (self.e.dir / "denylist.txt").read_text(),
               "GOUMAR_SALT": (self.e.dir / "salt").read_text()}
        p = self.e.write("a.md", "Plumbo Industries")
        r = self.e.run("hook.py", [str(p)], env_override=env,
                       drop=("GOUMAR_DENYLIST_FILE", "GOUMAR_SALT_FILE"))
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_missing_path_stops(self):
        self.assertEqual(self.e.run("hook.py", [str(self.e.dir / "nope.md")]).returncode, 2)


class NoLeakTests(Base):
    BANNED = ("Zebrov", "Зебров", "Plumbo", "600 111", "600111", "10.20.30.40", "deploy@prodbox", "sk-abcdefghijklmnop1234")

    def test_banned_text_never_printed(self):
        text = ("Zebrov Зеброва Plumbo Industries +34 600 111 222 10.20.30.40 deploy@prodbox "
                "sk-abcdefghijklmnop1234 /Users/x")
        p = self.e.write("Zebrov-notes.md", text)  # the file NAME is banned too
        r = self.e.run("hook.py", [str(self.e.dir / "work")])
        self.assertEqual(r.returncode, 1)
        out = r.stdout + r.stderr
        for w in self.BANNED + ("Zebrov-notes", "zebrov"):
            self.assertNotIn(w, out)
            self.assertNotIn(w.lower(), out.lower())
        self.assertIn("<redacted-path:", r.stdout)
        self.assertEqual(set(rules(r.stdout)) >= {"hash-name", "deny-phrase", "phone", "ipv4", "user-at-host", "secret-key", "abs-path"}, True)

    def test_error_paths_do_not_leak(self):
        p = self.e.write("a.md", "Zebrov")
        (self.e.dir / "denylist.version").write_text("bad\n")
        r = self.e.run("hook.py", [str(p)])
        self.assertNotIn("Zebrov", r.stdout + r.stderr)


class GitModeTests(Base):
    def setUp(self):
        super().setUp()
        self.repo = self.e.dir / "repo"
        self.repo.mkdir()
        g = lambda *a: subprocess.run(["git", "-C", str(self.repo)] + list(a), check=True, capture_output=True)
        g("init", "-q")
        g("config", "user.email", "t@example.invalid")
        g("config", "user.name", "t")
        self.g = g

    def hook(self, *args, stdin=""):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GOUMAR_")}
        env.update(self.e.env)
        import sys
        from support import PRIV
        return subprocess.run([sys.executable, str(PRIV / "hook.py")] + list(args), input=stdin, text=True,
                              capture_output=True, env=env, cwd=str(self.repo))

    def test_staged_scans_index_not_worktree(self):
        (self.repo / "a.md").write_text("Zebrov")
        self.g("add", "a.md")
        (self.repo / "a.md").write_text("clean now")  # worktree clean, index dirty
        r = self.hook("--staged")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rules(r.stdout), ["hash-name"])

    def test_pushed_catches_word_removed_in_later_commit_and_message(self):
        (self.repo / "a.md").write_text("Zebrov")
        self.g("add", "a.md")
        self.g("commit", "-q", "-m", "first")
        (self.repo / "a.md").write_text("clean")
        self.g("commit", "-qam", "Plumbo Industries cleanup\n\nCo-Authored-By: X <noreply@anthropic.com>")
        sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True).stdout.strip()
        r = self.hook("--pushed", stdin="refs/heads/main %s refs/heads/main %s\n" % (sha, "0" * 40))
        self.assertEqual(r.returncode, 1)
        got = sorted(rules(r.stdout))
        self.assertEqual(got, ["deny-phrase", "hash-name"])  # blob in history + message; trailer email ignored

    def test_pushed_clean(self):
        (self.repo / "a.md").write_text("fine")
        self.g("add", "a.md")
        self.g("commit", "-q", "-m", "ok")
        sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True).stdout.strip()
        r = self.hook("--pushed", stdin="refs/heads/main %s refs/heads/main %s\n" % (sha, "0" * 40))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
