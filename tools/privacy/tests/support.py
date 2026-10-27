"""Test fixtures. Only invented words: Zebrov, Quorvex, Plumbo, a fake phone."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIV = HERE.parent
sys.path.insert(0, str(PRIV))

import config  # noqa: E402
import hashlist  # noqa: E402

SALT = b"unit-test-salt"
RAW_NAMES = ["Зебров", "Ivan Zebrov", "Quorvex Lumina Sur", "@zebrov_fan"]
DENY = "# comment\nPlumbo Industries\nBlorp Spy\nпоставщик Фиктивный\nphone: +34 600 111 222\n"
FAKE_PHONE = "+34 600 111 222"


class Env:
    """A temp dir with salt, denylist, hash list, version file and an env dict."""

    def __init__(self, names=None, deny=DENY, with_canary=True):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.dir = d
        (d / "salt").write_text(SALT.decode() + "\n")
        (d / "denylist.txt").write_text(deny)
        hashes, _ = hashlist.build_hashes(names if names is not None else RAW_NAMES, SALT)
        if not with_canary:
            hashes.discard(config.canary_hash(SALT))
        (d / "names.hashes").write_text("\n".join(sorted(hashes)) + "\n")
        version = config.compute_version(deny, hashes)
        (d / "denylist.version").write_text(version + "\n")
        self.version = version
        self.env = {
            "GOUMAR_DENYLIST_FILE": str(d / "denylist.txt"),
            "GOUMAR_NAMES_HASHES_FILE": str(d / "names.hashes"),
            "GOUMAR_SALT_FILE": str(d / "salt"),
            "GOUMAR_VERSION_FILE": str(d / "denylist.version"),
        }

    def write(self, name, content, mode="w"):
        p = self.dir / "work" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, mode) as fh:
            fh.write(content)
        return p

    def run(self, script, args=(), stdin="", env_override=None, drop=()):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GOUMAR_")}
        env.update(self.env)
        env.update(env_override or {})
        for k in drop:
            env.pop(k, None)
        return subprocess.run([sys.executable, str(PRIV / script)] + list(args), input=stdin,
                              capture_output=True, text=True, env=env)

    def close(self):
        self.tmp.cleanup()


class Base(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.addCleanup(self.e.close)
