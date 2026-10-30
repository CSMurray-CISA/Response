import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PlatformShellTests(unittest.TestCase):
    def test_shell_links_all_three_tools(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('src="advisory-analysis.html"', html)
        self.assertIn('data-src="vulnerability-dashboard.html"', html)
        self.assertIn('data-src="ssvc-dashboard.html"', html)
        self.assertIn('data-src="kev-ssvc.html"', html)

    def test_original_vulnerability_dashboard_is_standalone(self):
        html = (ROOT / "vulnerability-dashboard.html").read_text(encoding="utf-8")
        self.assertIn("<title>Vulnerability Dashboard</title>", html)
        self.assertIn("services.nvd.nist.gov/rest/json/cves/2.0", html)
        self.assertNotIn('src="vulnerability-dashboard.js"', html)
        self.assertIn('href="platform-theme.css"', html)

    def test_ssvc_uses_shared_platform_theme(self):
        html = (ROOT / "ssvc-dashboard.html").read_text(encoding="utf-8")
        self.assertIn('class="advisory-ui ssvc-dashboard"', html)
        self.assertIn('href="platform-theme.css"', html)
        self.assertTrue((ROOT / "platform-theme.css").is_file())

    def test_each_tool_file_exists(self):
        for name in (
            "advisory-analysis.html",
            "vulnerability-dashboard.html",
            "ssvc-dashboard.html",
            "kev-ssvc.html",
            "kev-ssvc.css",
            "kev-ssvc.js",
            "platform-preferences.js",
            "app.js",
            "styles.css",
        ):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_preferences_are_available_on_every_page(self):
        shell = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-pref-theme="dark"', shell)
        self.assertIn('data-pref-theme="light"', shell)
        self.assertIn('data-pref-font="normal"', shell)
        self.assertIn('data-pref-font="large"', shell)
        self.assertIn('data-pref-font="extra-large"', shell)
        for name in (
            "advisory-analysis.html",
            "vulnerability-dashboard.html",
            "ssvc-dashboard.html",
            "kev-ssvc.html",
        ):
            html = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn('src="platform-preferences.js"', html, name)

    def test_staged_kev_dataset_is_present(self):
        dataset = ROOT / "data" / "kev-ssvc.json"
        self.assertTrue(dataset.is_file())
        self.assertGreater(dataset.stat().st_size, 1000)

    def test_kev_table_uses_requested_column_order(self):
        html = (ROOT / "kev-ssvc.html").read_text(encoding="utf-8")
        expected = [
            'data-sort="vulnerabilityName"',
            'data-sort="cvss"',
            'data-sort="technicalImpact"',
            'data-sort="automatable"',
            'data-sort="cwes"',
            'data-sort="dueDate"',
            'data-sort="forensicTriage"',
        ]
        positions = [html.index(value) for value in expected]
        self.assertEqual(positions, sorted(positions))
        script = (ROOT / "kev-ssvc.js").read_text(encoding="utf-8")
        script_positions = [script.index(f'key: "{key}"') for key in (
            "vulnerabilityName", "cvss", "technicalImpact", "automatable", "cwes", "dueDate", "forensicTriage"
        )]
        self.assertEqual(script_positions, sorted(script_positions))

    def test_kev_exploitation_controls_are_removed(self):
        html = (ROOT / "kev-ssvc.html").read_text(encoding="utf-8")
        script = (ROOT / "kev-ssvc.js").read_text(encoding="utf-8")
        self.assertNotIn('id="exploitationFilter"', html)
        self.assertNotIn('key: "exploitation"', script)
        self.assertIn('id="forensicTriageFilter"', html)


if __name__ == "__main__":
    unittest.main()
