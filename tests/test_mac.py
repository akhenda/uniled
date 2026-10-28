"""Regression tests for device identity across UniLED transports."""

import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "uniled_mac", Path(__file__).parents[1] / "custom_components/uniled/lib/mac.py"
)
mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac)


class MacIdentityTests(unittest.TestCase):
    def test_transport_formats_identify_same_controller(self):
        self.assertTrue(mac.same_mac("e8:06:90:69:75:ce", "E8:06:90:69:75:CE"))
        self.assertTrue(mac.same_mac("E8-06-90-69-75-CE", "e806906975ce"))

    def test_nearby_controllers_are_not_merged(self):
        self.assertFalse(mac.same_mac("e8:06:90:69:75:ce", "e8:06:90:69:75:cf"))

    def test_non_mac_identifiers_do_not_match(self):
        for value in (None, "mesh-identifier", "xyz", "zz:06:90:69:75:ce"):
            with self.subTest(value=value):
                self.assertFalse(mac.same_mac(value, value))


if __name__ == "__main__":
    unittest.main()
