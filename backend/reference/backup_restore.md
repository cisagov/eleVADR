# eleVADR backup and restore

Stage 10 backs up persistent platform state that must move together: MongoDB documents plus `storage/users/` report and retained-PCAP files.

## Backup

Run `backup_elevadr.bat`. By default it writes a timestamped ZIP under `backups/`; an optional destination path may be supplied.

The archive contains a versioned `manifest.json`, one BSON sequence per MongoDB collection, and persistent files under `storage/users/`. The manifest records document/file counts, SHA-256 hashes, sizes, database name, and non-secret retention/quota settings.

`.elevadr-platform.env`, MongoDB root passwords, JWT secrets, Docker internals, browser sessions, and temporary analysis files are excluded. User password hashes remain part of the MongoDB user records so restored accounts continue to work.

For the most consistent backup, do not start analyses or mutate saved reports/captures while backup is running.

## Validate

Run `validate_elevadr_backup.bat <backup.zip>`. This is non-destructive and checks format, safe archive paths, BSON document counts, storage sizes, and SHA-256 hashes.

## Restore

Validate first. Stop the eleVADR backend so users cannot mutate state, but leave MongoDB running. Then run `restore_elevadr.bat <backup.zip> --yes`.

Restore refuses to run without `--yes`, validates again, replaces storage and MongoDB documents, and attempts rollback of prior local state if restoration raises an error. Restart eleVADR and run `run_platform_regression_tests.bat` afterward.

## Backup confidentiality

Backups contain sensitive operational data, including report content, retained PCAPs, usernames, audit metadata, and password hashes. Plain ZIP backups are integrity-checked but are not confidential and must be protected accordingly.

When `ELEVADR_BACKUP_PASSPHRASE` is set for the backup process, eleVADR writes an authenticated encrypted `.evbackup` archive. Validation and restore require the same passphrase. The passphrase itself is never written into the backup manifest and should not be committed to source control.
