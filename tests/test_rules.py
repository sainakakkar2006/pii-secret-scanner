import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from secret_scanner.cli import main
from secret_scanner.rules import shannon_entropy
from secret_scanner.scanner import scan_path

# Fake values are built at runtime so this file never contains a string that
# looks like a real credential (GitHub push protection would block it).
FAKE_GOOGLE_KEY = "AIza" + "Sy" + "Fake0" * 6 + "abc"
RANDOM_TOKEN = "q8Zr2LmX0vTb7YkN4pWs1HdC9gEa6JuF"


def scan_text(text, *, include_pii=False, name="config.py"):
    with tempfile.TemporaryDirectory() as temp_name:
        path = Path(temp_name) / name
        path.write_text(text, encoding="utf-8")
        return scan_path(path, include_pii=include_pii)


class AssignmentRuleTests(unittest.TestCase):
    def test_prefixed_secret_names_are_detected(self):
        # v0.1 missed all four of these because of a \b before the keyword.
        text = (
            'GEMINI_API_KEY = "abcd1234efgh"\n'
            "OPENAI_API_KEY=abc123def456\n"
            "DB_PASSWORD=hunter2hunter2\n"
            'STRIPE_SECRET_KEY = "sk_test_abc123"\n'
        )
        findings = scan_text(text)
        self.assertEqual([f.line for f in findings], [1, 2, 3, 4])
        self.assertTrue(all(f.rule == "Environment assignment with secret-like name" for f in findings))

    def test_references_to_secrets_are_not_findings(self):
        text = (
            'API_KEY = os.environ.get("API_KEY")\n'
            'password = getenv("DB_PASSWORD")\n'
            "TOKEN=${GITHUB_TOKEN}\n"
            "secret = None\n"
            "token = load_token(path)\n"
            "token = 0\n"
            'GEMINI_API_KEY = "your-gemini-api-key-here"\n'
            "SECRET_KEY=changeme\n"
        )
        self.assertEqual(scan_text(text), [])


class GoogleKeyTests(unittest.TestCase):
    def test_google_api_key_is_high_and_reported_once(self):
        findings = scan_text(f'GEMINI_API_KEY = "{FAKE_GOOGLE_KEY}"\n', name="DEPLOY.md")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "Google API key")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertNotIn("Fake0Fake0", findings[0].value)


class EntropyTests(unittest.TestCase):
    def test_entropy_of_uniform_string(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_random_token_is_flagged(self):
        findings = scan_text(f"value: {RANDOM_TOKEN}\n", name="settings.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "High entropy token")

    def test_git_sha_and_long_identifiers_are_not_flagged(self):
        text = (
            "commit 3f786850e387550fdab836ed7e6dc881de23001b\n"
            "def test_scans_directories_and_ignores_binary_files(self):\n"
            "MAX_RETRIES_BEFORE_FALLING_BACK_TO_KEYWORDS = 3\n"
        )
        self.assertEqual(scan_text(text), [])


class PiiTests(unittest.TestCase):
    PII_TEXT = (
        "ssn: 123-45-6789\n"
        "card: 4111 1111 1111 1111\n"
        "bad card: 4111 1111 1111 1112\n"
        "owner: jane.doe@gmail.com\n"
        "placeholder: someone@example.com\n"
        "not an ssn: 000-12-3456\n"
    )

    def test_pii_is_off_by_default(self):
        self.assertEqual(scan_text(self.PII_TEXT, name="notes.txt"), [])

    def test_pii_rules_with_validators(self):
        findings = scan_text(self.PII_TEXT, include_pii=True, name="notes.txt")
        by_line = {f.line: f for f in findings}
        self.assertEqual(sorted(by_line), [1, 2, 4])
        self.assertEqual(by_line[1].rule, "US Social Security number")
        self.assertEqual(by_line[2].rule, "Payment card number")
        self.assertEqual(by_line[4].rule, "Email address")
        self.assertTrue(all(f.category == "pii" for f in findings))
        self.assertNotIn("45-67", by_line[1].value)

    def test_cli_pii_flag_changes_exit_code(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "export.txt"
            path.write_text("ssn: 123-45-6789\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                without = main(["scan", str(path)])
                with_pii = main(["scan", str(path), "--pii"])
        self.assertEqual(without, 0)
        self.assertEqual(with_pii, 1)


if __name__ == "__main__":
    unittest.main()
