"""Wave 3: owner-scoped saved query lifecycle without requiring a live MongoDB."""
import unittest
from types import SimpleNamespace
from backend_bryan.auth.topology_query_store import MongoTopologyQueryStore, validate_query


class FakeResult:
    def __init__(self, deleted_count=0):
        self.deleted_count = deleted_count


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def sort(self, key, direction):
        return FakeCursor(sorted(self.rows, key=lambda row: row[key], reverse=direction == -1))

    def limit(self, amount):
        return self.rows[:amount]


class FakeCollection:
    def __init__(self):
        self.rows = {}

    def update_one(self, selector, update, upsert=False):
        key = (selector['owner_id'], selector['query_id'])
        self.rows[key] = {**selector, **update['$set']}

    def find(self, selector):
        return FakeCursor([v for (owner, _), v in self.rows.items() if owner == selector['owner_id']])

    def delete_one(self, selector):
        key = (selector['owner_id'], selector['query_id'])
        existed = key in self.rows
        self.rows.pop(key, None)
        return FakeResult(int(existed))


class TopologyQueryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.store = MongoTopologyQueryStore(SimpleNamespace())
        self.store.collection = FakeCollection()

    def test_empty_list_and_owner_isolation(self):
        self.assertEqual(self.store.list_for_owner('alice'), [])
        created = self.store.save('alice', {'name': 'PLC', 'query': {'type': 'OT'}})
        self.assertEqual(self.store.list_for_owner('bob'), [])
        self.assertEqual(self.store.list_for_owner('alice')[0]['id'], created['id'])
        self.assertFalse(self.store.delete('bob', created['id']))
        self.assertEqual(len(self.store.list_for_owner('alice')), 1)

    def test_create_update_recall_delete(self):
        first = self.store.save('alice', {'name': 'Original', 'query': {'service': 'modbus'}})
        second = self.store.save('alice', {'id': first['id'], 'name': 'Updated', 'query': {'minCount': 3}})
        self.assertEqual(second['id'], first['id'])
        self.assertEqual(self.store.list_for_owner('alice')[0]['query'], {'minCount': 3})
        self.assertEqual(len(self.store.list_for_owner('alice')), 1)
        self.assertTrue(self.store.delete('alice', first['id']))
        self.assertEqual(self.store.list_for_owner('alice'), [])

    def test_invalid_payloads(self):
        invalid = [None, [], {'bad': True}, {'minCount': True}, {'minCount': 0}, {'suspicious': 'yes'}, {'service': ''}, {'service': ' '}, {'service': 'x' * 121}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_query(value)
        for value in ['', ' ', 'x' * 101]:
            with self.subTest(name=value), self.assertRaises(ValueError):
                self.store.save('alice', {'name': value, 'query': {}})
        for value in ['bad/path', 'bad\\path', 'bad.id', '$bad']:
            with self.subTest(id=value), self.assertRaises(ValueError):
                self.store.save('alice', {'id': value, 'name': 'Valid', 'query': {}})

    def test_same_query_reusable_between_reports(self):
        saved = self.store.save('alice', {'name': 'External', 'query': {'suspicious': True}})
        # Saved query definitions are report-independent; each report supplies its own graph.
        self.assertNotIn('reportId', saved)
        self.assertEqual(self.store.list_for_owner('alice')[0]['query'], {'suspicious': True})


if __name__ == '__main__':
    unittest.main()
