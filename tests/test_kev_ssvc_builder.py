import json
import tempfile
import unittest
from pathlib import Path

from scripts import build_kev_ssvc as builder


class KevSsvcBuilderTests(unittest.TestCase):
    def test_vulnrichment_path_uses_thousand_bucket(self):
        self.assertEqual(
            builder.vulnrichment_relpath("CVE-2026-73851"),
            Path("2026/73xxx/CVE-2026-73851.json"),
        )
        self.assertEqual(
            builder.vulnrichment_relpath("CVE-2024-4947"),
            Path("2024/4xxx/CVE-2024-4947.json"),
        )

    def test_cna_cvss_and_cwe_take_precedence_while_cisa_supplies_ssvc(self):
        record = {
            "containers": {
                "cna": {
                    "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
                },
                "adp": [{
                    "title": "CISA ADP Vulnrichment",
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [{"other": {"type": "ssvc", "content": {
                        "version": "2.0.3",
                        "options": [
                            {"Exploitation": "active"},
                            {"Automatable": "yes"},
                            {"Technical Impact": "total"},
                        ],
                    }}}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-20"}]}],
                }],
            }
        }
        row = builder.build_entry({
            "cveID": "CVE-2026-12345",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example vulnerability",
            "dateAdded": "2026-10-01",
            "dueDate": "2026-10-22",
            "forensicTriage": "Yes",
        }, record)
        self.assertEqual(row["cwes"], ["CWE-79"])
        self.assertEqual(row["cweSource"], "CNA")
        self.assertEqual(row["cvss"]["score"], 9.8)
        self.assertEqual(row["technicalImpact"], "total")
        self.assertEqual(row["automatable"], "yes")
        self.assertEqual(row["forensicTriage"], "yes")

    def test_kev_fallback_keeps_unknown_ssvc_and_forensic_triage(self):
        row = builder.build_entry({
            "cveID": "CVE-2020-1234",
            "vendorProject": "Example",
            "product": "Legacy",
            "vulnerabilityName": "Legacy vulnerability",
            "dateAdded": "2022-01-01",
            "dueDate": "2022-01-22",
            "forensicTriage": "No",
        }, {})
        self.assertEqual(row["ssvcSource"], "KEV")
        self.assertEqual(row["technicalImpact"], "unknown")
        self.assertEqual(row["automatable"], "unknown")
        self.assertEqual(row["forensicTriage"], "no")


if __name__ == "__main__":
    unittest.main()
