import unittest

from support import Base, Env, SALT
import config
import normalize
import hashlist

try:
    import wordfreq  # noqa: F401
    HAVE_WF = True
except ImportError:
    HAVE_WF = False


@unittest.skipUnless(HAVE_WF, "wordfreq not installed")
class HashlistTests(Base):
    def build(self, names, **kw):
        return self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "salt"),
                                          "--out", str(self.e.dir / "out.hashes")] + kw.get("args", []),
                          stdin="\n".join(names) + "\n")

    def test_counts_only_and_no_names_in_output(self):
        r = self.build(["Zebrov Ivan", "fix", "test"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"received=3 dropped_dictionary=\d+ kept=\d+ total=\d+")
        for word in ("Zebrov", "zebr", "Ivan"):
            self.assertNotIn(word.lower(), (r.stdout + r.stderr).lower().replace("received", ""))

    def test_dictionary_words_dropped(self):
        h, counts = hashlist.build_hashes(["fix", "тест", "sur"], SALT)
        self.assertEqual(counts["dropped_dictionary"], 3)
        self.assertEqual(counts["kept"], 1)  # canary only

    def test_multiword_kept_while_unigrams_dropped(self):
        h, counts = hashlist.build_hashes(["Job Spy"], SALT)
        self.assertEqual(counts["dropped_dictionary"], 2)
        self.assertIn(config.hash_key(SALT, normalize.normalize("Job Spy")), h)

    def test_proof_set_stop(self):
        with self.assertRaises(hashlist.ProofError):
            hashlist.build_hashes(["fix"], SALT, proof=["@fix"])
        r = self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "salt"),
                                       "--out", str(self.e.dir / "o"), "--proof",
                                       str(self.e.write("proof.txt", "fix\n"))], stdin="fix\n")
        self.assertEqual(r.returncode, 3)
        self.assertNotIn("fix", r.stdout + r.stderr.replace("hashlist: STOP", ""))

    def test_proof_set_accepts_hashes(self):
        h = config.hash_key(SALT, normalize.normalize("fix"))
        with self.assertRaises(hashlist.ProofError):
            hashlist.build_hashes(["fix"], SALT, proof=[h])

    def test_proof_without_clash_passes(self):
        hashlist.build_hashes(["fix", "Zebrov"], SALT, proof=["Zebrov"])

    def test_merge_only_grows(self):
        first = self.e.dir / "a.hashes"
        r1 = self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "salt"), "--out", str(first)],
                        stdin="Zebrov\n")
        self.assertEqual(r1.returncode, 0)
        r2 = self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "salt"), "--out", str(first),
                                        "--merge-into", str(first)], stdin="Quorvex\n")
        self.assertEqual(r2.returncode, 0)
        merged = first.read_text().split()
        self.assertIn(config.hash_key(SALT, normalize.normalize("Zebrov")), merged)
        self.assertIn(config.hash_key(SALT, normalize.normalize("Quorvex")), merged)
        self.assertEqual(len(merged), 3)  # zebr, quorvex, canary

    def test_merge_into_missing_file_fails(self):
        r = self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "salt"), "--out",
                                       str(self.e.dir / "o"), "--merge-into", str(self.e.dir / "nope")], stdin="x\n")
        self.assertEqual(r.returncode, 2)

    def test_missing_salt_fails(self):
        r = self.e.run("hashlist.py", ["build", "--salt-file", str(self.e.dir / "nosalt"), "--out",
                                       str(self.e.dir / "o")], stdin="x\n")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
