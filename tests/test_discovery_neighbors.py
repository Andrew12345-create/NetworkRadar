import json, unittest
from types import SimpleNamespace
from networkradar_modules.discovery.neighbors import collect_windows_neighbor_cache, merge_reachable_neighbors, parse_windows_neighbor_rows

SAMPLE=[
{"IPAddress":"192.168.100.21","LinkLayerAddress":"5e-11-22-33-44-55","State":"Reachable","InterfaceIndex":8},
{"IPAddress":"192.168.100.22","LinkLayerAddress":"00-11-22-33-44-66","State":"Stale","InterfaceIndex":8},
{"IPAddress":"192.168.101.23","LinkLayerAddress":"00-11-22-33-44-77","State":"Reachable","InterfaceIndex":8},
{"IPAddress":"192.168.100.24","LinkLayerAddress":"01-11-22-33-44-88","State":"Reachable","InterfaceIndex":8}]

class NeighborParserTests(unittest.TestCase):
 def test_only_reachable_in_scope_unicast_rows(self):
  rows=parse_windows_neighbor_rows(SAMPLE,"192.168.100.0/24")
  self.assertEqual([r["ip"] for r in rows],["192.168.100.21"])
  self.assertEqual(rows[0]["mac"],"5E:11:22:33:44:55")
  self.assertTrue(rows[0]["mac_locally_administered"])
 def test_single_json_object(self):
  row={"IPAddress":"192.168.100.1","LinkLayerAddress":"00:11:22:33:44:55","State":"Reachable","InterfaceIndex":8}
  self.assertEqual(parse_windows_neighbor_rows(json.dumps(row),"192.168.100.0/24")[0]["interface_index"],8)
 def test_invalid_scope_json_and_ipv6_fail_closed(self):
  self.assertEqual(parse_windows_neighbor_rows(SAMPLE,"not-a-network"),[])
  self.assertEqual(parse_windows_neighbor_rows("{bad","192.168.100.0/24"),[])
  self.assertEqual(parse_windows_neighbor_rows(SAMPLE,"2001:db8::/64"),[])
 def test_interface_index_can_be_scoped(self):
  rows=parse_windows_neighbor_rows(SAMPLE,"192.168.100.0/24",interface_index=9)
  self.assertEqual(rows,[])

class NeighborCollectionTests(unittest.TestCase):
 def test_read_only_powershell_collection(self):
  calls=[]
  def runner(command,**kwargs):
   calls.append(command); return SimpleNamespace(returncode=0,stdout=json.dumps(SAMPLE),stderr="")
  result=collect_windows_neighbor_cache("192.168.100.0/24",runner=runner,platform="nt")
  self.assertEqual(result["status"],"ONLINE")
  self.assertEqual(len(result["records"]),1)
  self.assertIn("Get-NetNeighbor",calls[0][-1])
  self.assertNotIn("-ExecutionPolicy",calls[0])
 def test_non_windows_unavailable(self):
  self.assertEqual(collect_windows_neighbor_cache("192.168.100.0/24",platform="linux")["status"],"UNAVAILABLE")
 def test_command_error_reported(self):
  result=collect_windows_neighbor_cache("192.168.100.0/24",runner=lambda *a,**k:SimpleNamespace(returncode=1,stdout="",stderr="Access denied"),platform="nt")
  self.assertEqual(result["status"],"ERROR")
  self.assertIn("Access denied",result["detail"])

class NeighborMergeTests(unittest.TestCase):
 def test_randomized_mac_added_without_model_claim(self):
  rows=parse_windows_neighbor_rows(SAMPLE,"192.168.100.0/24")
  result=merge_reachable_neighbors([],rows)
  self.assertEqual(len(result),1); self.assertEqual(result[0]["vendor"],"Unknown")
  self.assertEqual(result[0]["device_type"],"Unclassified device")
  self.assertIn("randomized or locally assigned",result[0]["_extra"][0][1])
 def test_conflicting_mac_is_not_overwritten(self):
  rows=parse_windows_neighbor_rows(SAMPLE,"192.168.100.0/24")
  result=merge_reachable_neighbors([{"ip":"192.168.100.21","mac":"00:AA:BB:CC:DD:EE"}],rows)
  self.assertEqual(result[0]["mac"],"00:AA:BB:CC:DD:EE")
  self.assertIn("conflicts",result[0]["_extra"][0][1])
 def test_existing_ip_is_not_duplicated(self):
  rows=parse_windows_neighbor_rows(SAMPLE,"192.168.100.0/24")
  result=merge_reachable_neighbors([{"ip":"192.168.100.21","mac":"5E:11:22:33:44:55"}],rows)
  self.assertEqual(len(result),1)

if __name__=="__main__": unittest.main()
