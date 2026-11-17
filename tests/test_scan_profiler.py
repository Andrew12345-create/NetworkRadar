import time
import unittest

from networkradar_modules.diagnostics.scan_profiler import ScanProfiler, measure_phase


class ScanProfilerTests(unittest.TestCase):
    def test_accumulates_named_phases_and_sorts_by_duration(self):
        profiler = ScanProfiler(3, "192.168.100.0/24")
        with profiler.measure("discovery"):
            time.sleep(0.015)
        with profiler.measure("identity"):
            time.sleep(0.005)
        with profiler.measure("discovery"):
            time.sleep(0.005)

        result = profiler.snapshot()
        self.assertEqual(result["scan_number"], 3)
        self.assertEqual(result["network"], "192.168.100.0/24")
        self.assertEqual(result["phase_count"], 2)
        self.assertEqual(result["phases"][0]["name"], "discovery")
        self.assertEqual(result["phases"][0]["calls"], 2)
        self.assertGreater(result["phases"][0]["duration_seconds"], 0)
        self.assertEqual(result["slowest_phase"], "discovery")

    def test_records_error_type_and_propagates_exception(self):
        profiler = ScanProfiler(1)
        with self.assertRaisesRegex(ValueError, "expected"):
            with profiler.measure("failing-phase"):
                raise ValueError("expected")
        phase = profiler.snapshot()["phases"][0]
        self.assertEqual(phase["errors"], 1)
        self.assertEqual(phase["last_error_type"], "ValueError")

    def test_optional_profiler_is_a_noop(self):
        with measure_phase(None, "not-measured"):
            pass


if __name__ == "__main__":
    unittest.main()
