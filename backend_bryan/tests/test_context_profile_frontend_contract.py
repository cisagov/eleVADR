from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_authenticated_context_profile_sync_contract():
    service=(ROOT/'frontend/src/app/services/contextProfileService.ts').read_text(encoding='utf-8')
    ui=(ROOT/'frontend/src/app/components/DetectionConfiguration/DetectionConfiguration.tsx').read_text(encoding='utf-8')
    assert '/api/v1/context-profiles' in service and 'authenticatedFetch' in service
    assert 'saveRemoteContextProfile' in ui and 'listRemoteContextProfiles' in ui
    assert 'Profile saved locally' in ui and 'synced to your account' in ui
