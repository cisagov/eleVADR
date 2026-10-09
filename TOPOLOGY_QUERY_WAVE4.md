# Topology Query Wave 4

Adds bounded 1-4 hop observed-communication traversal to the Graph Query Explorer. Set an optional starting asset IP, hop count, and traversal direction. Without a starting asset, traversal starts from assets matching existing asset filters. The query executes against all relationships present in the loaded report, while graph rendering remains bounded. Query definitions can be saved through the existing MongoDB-backed owner-scoped store.

Important: paths are **chains of observed communication edges**, not proof of IP routing, physical connections, firewall reachability, or exploit paths. Existing service, finding and suspicious filters restrict traversable edges.

Run `python -m unittest backend_bryan.tests.test_topology_query_wave3 backend_bryan.tests.test_topology_query_wave4 -v` and from `frontend`, `npm run type-check` and `npm run build`.
