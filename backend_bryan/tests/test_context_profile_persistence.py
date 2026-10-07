from backend_bryan.auth.context_profile_store import MongoContextProfileStore

def test_context_profile_store_source_contract():
    import inspect
    source=inspect.getsource(MongoContextProfileStore)
    assert '"owner_id":owner_id,"profile_id":pid' in source.replace(' ', '') or '"owner_id": owner_id, "profile_id": pid' in source
    assert 'context_profiles_owner_id' in source
