import unittest

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import normalize as n  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_translit_and_case(self):
        self.assertEqual(n.normalize("Зебров"), n.normalize("ZEBROV"))
        self.assertEqual(n.transliterate("щука"), "shchuka")

    def test_leading_at_punctuation_and_separators(self):
        for s in ("@zebrov", "zebrov!", "zebrov_", "a/zebrov", "x.zebrov", "x-zebrov", "u@zebrov", "t:zebrov"):
            self.assertIn("zebr", n.normalize(s).split(), s)

    def test_accents_removed_nfkc(self):
        self.assertEqual(n.normalize("Peña"), n.normalize("pena"))
        self.assertEqual(n.normalize("ｚｅｂｒｏｖ"), n.normalize("zebrov"))  # fullwidth

    def test_russian_case_endings_collapse(self):
        base = n.normalize("Зебров")
        for form in ("Зеброва", "Зебровым", "Зебровой", "Зебровы", "Зебровых", "Зебровe", "Зебровu"):
            self.assertEqual(n.normalize(form), base, form)

    def test_variant_folding(self):
        groups = [("Жебров", "Zhebrov", "Jebrov"), ("Хебров", "Khebrov", "Hebrov"),
                  ("Цебров", "Tsebrov", "Cebrov", "Tzebrov"),
                  ("Щебров", "Shchebrov", "Schebrov", "Shebrov"),
                  ("Юбров", "Yubrov", "Iubrov", "Ubrov"), ("Ябров", "Yabrov", "Iabrov", "Abrov"),
                  ("Сергей", "Sergey", "Sergei"), ("Зебров", "Zebbrov", "Zebrov")]
        for g in groups:
            self.assertEqual(len({n.normalize(x) for x in g}), 1, g)

    def test_folding_keeps_endings_consistent(self):
        self.assertEqual(n.normalize("Жебровым"), n.normalize("Jebrov"))
        self.assertEqual(n.normalize("Сергея"), n.normalize("Sergey"))

    def test_fold_table(self):
        self.assertEqual(n.fold("shch"), "sh")
        self.assertEqual(n.fold("zh"), "j")
        self.assertEqual(n.fold("ff"), "f")
        self.assertEqual(n.fold("ya"), "a")

    def test_spanish_plural(self):
        self.assertEqual(n.normalize("Zebrovs"), n.normalize("Zebrov"))

    def test_min_stem(self):
        self.assertEqual(n.normalize("ana"), "ana")

    def test_ngrams_up_to_three(self):
        toks = n.tokenize("one two three four")
        keys = [k for k, _, _ in n.ngrams(toks)]
        self.assertTrue(any(k.count(" ") == 2 for k in keys))
        self.assertFalse(any(k.count(" ") == 3 for k in keys))
        self.assertEqual(len(keys), 4 + 3 + 2)

    def test_token_offsets(self):
        t = n.tokenize("  hi @zebrov")
        self.assertEqual((t[1].start, t[1].end), (6, 12))


if __name__ == "__main__":
    unittest.main()
