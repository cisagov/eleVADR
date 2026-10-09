"""Apply Wave 7.7 route additions to the existing backend_bryan server, preserving newer routes."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
path = root / 'backend_bryan/integration/http_reference_server.py'
if not path.exists():
    sys.exit('Missing backend_bryan/integration/http_reference_server.py')
s = path.read_text(encoding='utf-8')
if 'TOPOLOGY_COMPARISONS_PATH' in s:
    sys.exit('Comparison routes already present; no changes made.')
anchors = [
    'TOPOLOGY_QUERIES_PATH = "/api/v1/topology-queries"',
    '_TOPOLOGY_QUERY_STORE: Any = None',
    '        if self.path == TOPOLOGY_QUERIES_PATH:',
    '        if self.path.startswith(f"{TOPOLOGY_QUERIES_PATH}/"):',
    '        if self.path == TOPOLOGY_QUERIES_PATH:',
    '        from backend_bryan.auth.topology_query_store import MongoTopologyQueryStore',
    '            _TOPOLOGY_QUERY_STORE = MongoTopologyQueryStore(_AUTH_SERVICE.config); _TOPOLOGY_QUERY_STORE.connect()',
    '        if _TOPOLOGY_QUERY_STORE is not None:',
]
if any(a not in s for a in anchors):
    sys.exit('Backend version differs from expected topology-query routes; no changes made.')
s=s.replace(anchors[0],anchors[0]+'\nTOPOLOGY_COMPARISONS_PATH = "/api/v1/topology-comparisons"',1)
s=s.replace(anchors[1],anchors[1]+'\n_TOPOLOGY_COMPARISON_STORE: Any = None',1)
# use first GET anchor only
get_route='''        if self.path == TOPOLOGY_COMPARISONS_PATH:
            principal = self._current_principal()
            if principal is None or not principal.authenticated:
                self._json(401, {"error": "authentication_required"}); return
            if _TOPOLOGY_COMPARISON_STORE is None:
                self._json(503, {"error": "comparison_store_unavailable"}); return
            self._json(200, {"comparisons": _TOPOLOGY_COMPARISON_STORE.list_for_owner(principal.user_id)})
            return

'''
s=s.replace(anchors[2],get_route+anchors[2],1)
delete_route='''        if self.path.startswith(f"{TOPOLOGY_COMPARISONS_PATH}/"):
            principal = self._current_principal()
            if principal is None or not principal.authenticated or _TOPOLOGY_COMPARISON_STORE is None:
                self._json(503, {"error": "comparison_store_unavailable"}); return
            comparison_id = self.path[len(TOPOLOGY_COMPARISONS_PATH)+1:].strip("/")
            if not _TOPOLOGY_COMPARISON_STORE.delete(principal.user_id, comparison_id):
                self._json(404, {"error": "comparison_not_found"}); return
            self._json(200, {"status": "deleted"}); return
'''
s=s.replace(anchors[3],delete_route+anchors[3],1)
post_route='''        if self.path == TOPOLOGY_COMPARISONS_PATH:
            if not self._require_write_access(): return
            principal = self._current_principal()
            if principal is None or not principal.authenticated or _TOPOLOGY_COMPARISON_STORE is None:
                self._json(503, {"error": "comparison_store_unavailable"}); return
            try:
                saved = _TOPOLOGY_COMPARISON_STORE.save(principal.user_id, self._read_json())
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": "invalid_comparison", "message": str(exc)}); return
            self._json(200, {"comparison": saved}); return
'''
post_idx=s.index('    def do_POST(')
s=s[:post_idx]+s[post_idx:].replace(anchors[4],post_route+anchors[4],1)
s=s.replace('global _AUTH_SERVICE, _REPORT_STORE, _CAPTURE_STORE, _AUDIT_STORE, _CONTEXT_PROFILE_STORE, _TOPOLOGY_QUERY_STORE', 'global _AUTH_SERVICE, _REPORT_STORE, _CAPTURE_STORE, _AUDIT_STORE, _CONTEXT_PROFILE_STORE, _TOPOLOGY_QUERY_STORE, _TOPOLOGY_COMPARISON_STORE',1)
s=s.replace(anchors[5],anchors[5]+'\n        from backend_bryan.auth.topology_comparison_store import MongoTopologyComparisonStore',1)
s=s.replace(anchors[6],anchors[6]+'\n            _TOPOLOGY_COMPARISON_STORE = MongoTopologyComparisonStore(_AUTH_SERVICE.config); _TOPOLOGY_COMPARISON_STORE.connect()',1)
s=s.replace(anchors[7],'''        if _TOPOLOGY_COMPARISON_STORE is not None:
            _TOPOLOGY_COMPARISON_STORE.close()
'''+anchors[7],1)
import ast
ast.parse(s)
backup=path.with_suffix('.py.wave7-backup')
backup.write_text(path.read_text(encoding='utf-8'),encoding='utf-8')
path.write_text(s,encoding='utf-8')
print('Patched backend routes successfully')
