"""Reconcile saved-analysis service and connection count metadata."""
import argparse
from backend_bryan.auth.env_runner import apply_platform_env
from backend_bryan.auth.config import load_auth_config
from backend_bryan.auth.report_store import MongoReportStore

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='Write metadata (default is preview)')
    args = parser.parse_args()
    if not apply_platform_env():
        raise RuntimeError('Platform environment not found; repair canceled')
    store = MongoReportStore(load_auth_config())
    store.connect()
    try:
        for owner in store._reports.distinct('owner_id'):
            print(f'Owner {owner}: {store.repair_activity_counts_for_owner(owner, dry_run=not args.apply)}')
    finally:
        store.close()

if __name__ == '__main__':
    main()
