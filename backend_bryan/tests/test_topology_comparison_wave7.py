import unittest
from unittest.mock import MagicMock
from backend_bryan.auth.topology_comparison_store import MongoTopologyComparisonStore, validate_comparison


class ComparisonTests(unittest.TestCase):
    def test_valid(self):
        result = validate_comparison({"name": "OT change", "baselineId": "a", "currentReportId": "b", "filter": "New"})
        self.assertEqual(result["filter"], "New")

    def test_rejects_unknown_fields_and_invalid_types(self):
        for payload in ({"name": "x", "baselineId": "a", "currentReportId": "b", "admin": True},
                        {"name": "x", "baselineId": "a", "currentReportId": "b", "queryOnly": "yes"},
                        {"name": "x", "baselineId": "a", "currentReportId": "b", "id": "../other"}):
            with self.assertRaises(ValueError):
                validate_comparison(payload)

    def test_owner_scoping(self):
        store = MongoTopologyComparisonStore(MagicMock())
        store.collection = MagicMock()
        store.collection.find.return_value.sort.return_value.limit.return_value = [{"data": {"id": "one"}}]
        store.list_for_owner("alice")
        store.collection.find.assert_called_with({"owner_id": "alice"})
        store.delete("bob", "one")
        store.collection.delete_one.assert_called_with({"owner_id": "bob", "comparison_id": "one"})
        store.save("alice", {"name": "test", "baselineId": "a", "currentReportId": "b"})
        self.assertEqual(store.collection.update_one.call_args.args[0]["owner_id"], "alice")


if __name__ == '__main__':
    unittest.main()
