"""Wave 4 traversal query schema validation and saved-query compatibility."""
import unittest
from backend_bryan.auth.topology_query_store import validate_query

class TraversalSchemaTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_query({"startAsset":"10.0.0.5","maxHops":3,"direction":"outbound"}), {"startAsset":"10.0.0.5","maxHops":3,"direction":"outbound"})
    def test_invalid_hops(self):
        for value in (0,5,True,1.5,"2"):
            with self.subTest(value=value), self.assertRaises(ValueError): validate_query({"maxHops":value})
    def test_invalid_direction(self):
        with self.assertRaises(ValueError): validate_query({"direction":"execute"})
    def test_unknown_fields(self):
        with self.assertRaises(ValueError): validate_query({"cypher":"MATCH (n) RETURN n"})

if __name__ == "__main__": unittest.main()
