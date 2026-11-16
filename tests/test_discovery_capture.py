import unittest
from networkradar_modules.discovery.capture import DHCP_CAPTURE_FIELDS, parse_tshark_field_registry, resolve_tshark_fields

def registry(*fields):
 return "\n".join("F\tDisplay name\t"+field+"\tFT_STRING" for field in fields)

class TSharkFieldTests(unittest.TestCase):
 def test_parse_field_registry_rows(self):
  self.assertEqual(parse_tshark_field_registry("P\tProtocol\tdhcp\n"+registry("dhcp.option.hostname","ip.src")),{"dhcp.option.hostname","ip.src"})
 def test_resolve_current_fields(self):
  result=resolve_tshark_fields(registry(*DHCP_CAPTURE_FIELDS))
  self.assertEqual(len(result["fields"]),len(DHCP_CAPTURE_FIELDS))
  self.assertEqual(result["missing_required"],[])
 def test_bootp_aliases(self):
  result=resolve_tshark_fields(registry("frame.time_epoch","ip.src","ip.dst","bootp.option.dhcp","bootp.hw.mac_addr","bootp.ip.your"))
  mapping=dict(result["fields"])
  self.assertEqual(mapping["dhcp.option.dhcp"],"bootp.option.dhcp")
  self.assertEqual(mapping["dhcp.hw.mac_addr"],"bootp.hw.mac_addr")
  self.assertEqual(result["missing_required"],[])
 def test_missing_optional_is_not_fatal(self):
  result=resolve_tshark_fields(registry("frame.time_epoch","ip.src","ip.dst","dhcp.option.dhcp","dhcp.hw.mac_addr","dhcp.ip.your"))
  self.assertEqual(result["missing_required"],[])
  self.assertTrue(result["missing_optional"])
 def test_missing_core_fields_reported(self):
  result=resolve_tshark_fields(registry("frame.time_epoch","ip.src"))
  self.assertIn("dhcp.hw.mac_addr",result["missing_required"])

if __name__=="__main__": unittest.main()
