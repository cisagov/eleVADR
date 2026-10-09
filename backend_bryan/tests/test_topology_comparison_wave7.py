"""Wave 7 saved-comparison lifecycle and owner-isolation regression tests."""
import unittest
from unittest.mock import MagicMock

from backend_bryan.auth.topology_comparison_store import (
    MongoTopologyComparisonStore,
    validate_comparison,
)


class FakeCollection:
    def __init__(self):
        self.documents = {}

    def update_one(self, selector, update, upsert=False):
        key = (selector['owner_id'], selector['comparison_id'])
        if key not in self.documents and not upsert:
            return
        self.documents[key] = {**selector, **update['$set']}

    def delete_one(self, selector):
        key = (selector['owner_id'], selector['comparison_id'])
        removed = self.documents.pop(key, None) is not None
        return type('DeleteResult', (), {'deleted_count': int(removed)})()

    def find(self, selector):
        items = [item for item in self.documents.values()
                 if item['owner_id'] == selector['owner_id']]
        return FakeCursor(items)


class FakeCursor:
    def __init__(self, items):
        self.items = items

    def sort(self, field, direction):
        self.items.sort(key=lambda item: item[field], reverse=direction < 0)
        return self

    def limit(self, count):
        return self.items[:count]


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.store = MongoTopologyComparisonStore(MagicMock())
        self.store.collection = FakeCollection()
        self.payload = {'name': 'OT change', 'baselineId': 'baseline-1',
                        'currentReportId': 'current-2', 'filter': 'New',
                        'findingsOnly': True, 'queryOnly': False}

    def test_valid_defaults_and_normalization(self):
        result = validate_comparison(self.payload)
        self.assertEqual(result['filter'], 'New')
        self.assertTrue(result['findingsOnly'])
        self.assertFalse(result['queryOnly'])
        self.assertEqual(validate_comparison({**self.payload, 'name': '  Test  '})['name'], 'Test')

    def test_rejects_unknown_fields_and_invalid_types(self):
        invalid = [
            {**self.payload, 'admin': True},
            {**self.payload, 'queryOnly': 'yes'},
            {**self.payload, 'id': '../other'},
            {**self.payload, 'name': ' '},
            {**self.payload, 'filter': 'Unexpected'},
            {**self.payload, 'baselineId': None},
            {**self.payload, 'currentReportId': ''},
            [], None,
        ]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_comparison(payload)

    def test_create_list_update_delete_lifecycle(self):
        saved = self.store.save('alice', self.payload)
        self.assertEqual(len(self.store.list_for_owner('alice')), 1)
        self.assertEqual(self.store.list_for_owner('alice')[0]['id'], saved['id'])
        updated = self.store.save('alice', {**self.payload, 'id': saved['id'], 'name': 'Updated'})
        self.assertEqual(updated['name'], 'Updated')
        self.assertEqual(len(self.store.list_for_owner('alice')), 1)
        self.assertEqual(self.store.list_for_owner('alice')[0]['name'], 'Updated')
        self.assertTrue(self.store.delete('alice', saved['id']))
        self.assertFalse(self.store.delete('alice', saved['id']))
        self.assertEqual(self.store.list_for_owner('alice'), [])

    def test_owner_isolation_for_same_identifier(self):
        saved = self.store.save('alice', {**self.payload, 'id': 'shared-id'})
        self.assertEqual(self.store.list_for_owner('bob'), [])
        self.assertFalse(self.store.delete('bob', saved['id']))
        self.store.save('bob', {**self.payload, 'id': 'shared-id', 'name': 'Bob comparison'})
        self.assertEqual(self.store.list_for_owner('alice')[0]['name'], 'OT change')
        self.assertEqual(self.store.list_for_owner('bob')[0]['name'], 'Bob comparison')
        self.assertTrue(self.store.delete('alice', saved['id']))
        self.assertEqual(len(self.store.list_for_owner('bob')), 1)

    def test_settings_do_not_contain_report_payloads(self):
        saved = self.store.save('alice', self.payload)
        self.assertNotIn('report', saved)
        self.assertNotIn('baselineReport', saved)
        self.assertEqual(saved['baselineId'], 'baseline-1')


if __name__ == '__main__':
    unittest.main()
