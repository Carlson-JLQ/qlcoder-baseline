from __future__ import annotations

import unittest
from pathlib import Path

from trace_viewer.repository import TraceRepository


ROOT = Path(__file__).resolve().parents[2]
SUCCESSFUL_CVES = {
    "CVE-2022-25842",
    "CVE-2022-32287",
    "CVE-2025-30177",
    "CVE-2025-24399",
    "CVE-2025-52520",
    "CVE-2025-26795",
    "CVE-2025-26864",
    "CVE-2025-53003",
    "CVE-2025-23015",
    "CVE-2025-1391",
    "CVE-2025-48734",
    "CVE-2025-27522",
    "CVE-2025-27531",
    "CVE-2025-2240",
}


class RepositoryIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = TraceRepository(ROOT)
        cls.runs = cls.repository.list_runs()
        cls.run_2240 = next(run for run in cls.runs if run["cve"] == "CVE-2025-2240")

    def test_discovers_all_current_output_runs(self) -> None:
        self.assertEqual(32, len(self.runs))

    def test_known_successful_cves_are_successful(self) -> None:
        actual = {run["cve"] for run in self.runs if run["status"] == "SUCCESS"}
        self.assertEqual(SUCCESSFUL_CVES, actual)

    def test_turns_are_derived_from_trace_results(self) -> None:
        self.assertEqual(498, self.run_2240["turns"])

    def test_tool_calls_pair_with_results(self) -> None:
        trace = self.repository.load_trace(self.run_2240["id"], "phase3_iter_2")
        stats = trace["stats"]
        self.assertEqual(74, stats["tool_call_count"])
        self.assertEqual(74, stats["tool_result_count"])
        self.assertEqual(0, stats["unmatched_tool_calls"])
        self.assertEqual(0, stats["unmatched_tool_results"])

    def test_trace_page_can_filter_tools(self) -> None:
        page = self.repository.get_trace_page(
            self.run_2240["id"], "phase3_iter_2", limit=250, kind="tool", tool="codeql"
        )
        self.assertGreaterEqual(page["total"], 1)
        self.assertTrue(all("codeql" in event["tool_name"].lower() for event in page["events"]))

    def test_artifact_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.repository.read_artifact(self.run_2240["id"], "../.env")

    def test_query_diff_is_available(self) -> None:
        diff = self.repository.query_diff(self.run_2240["id"], 1, 8)
        self.assertIn("CVE-2025-2240-query-iter-1.ql", diff["from"])
        self.assertIn("CVE-2025-2240-query-iter-8.ql", diff["to"])
        self.assertIn("@@", diff["diff"])


if __name__ == "__main__":
    unittest.main()
