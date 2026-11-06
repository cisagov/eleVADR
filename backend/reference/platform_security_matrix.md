# eleVADR platform security matrix

Stage 7 turns the platform role labels into enforced authorization boundaries. The backend is authoritative; frontend controls mirror the same policy for usability.

| Capability | Admin | Analyst | Read Only |
| --- | :---: | :---: | :---: |
| View/open own saved reports | Yes | Yes | Yes |
| View retained PCAP metadata | Yes | Yes | Yes |
| Upload/analyze PCAP | Yes | Yes | No |
| Re-analyze retained PCAP | Yes | Yes | No |
| Change Analysis Context/modules | Yes | Yes | No |
| Rename/delete own reports | Yes | Yes | No |
| Delete retained PCAP | Yes | Yes | No |
| Cancel analysis/discovery jobs | Yes | Yes | No |
| Change own password | Yes | Yes | Yes |
| Manage users/roles | Yes | No | No |

## Security rules

- Authentication remains disabled by default until explicitly enabled.
- JWTs use the fixed HS256 algorithm and reject tampered, expired, or incorrectly signed tokens.
- Passwords use Argon2 verification and are never stored in plaintext.
- Disabled accounts and current roles are resolved against MongoDB, so disabling an account or changing a role takes effect without waiting for an older JWT to expire.
- Saved reports and retained PCAPs remain owner-scoped. Cross-user object access returns not-found behavior rather than disclosing another user's object.
- Read-only enforcement occurs at the HTTP boundary before analysis, mutation, deletion, re-analysis, or cancellation work begins.
- User administration remains separately admin-only.
- The frontend hides or disables write controls for read-only accounts, but frontend state is never treated as authorization.
