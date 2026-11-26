# Release Publication Recovery

## Security requirements

- Recovery requires explicit maintainer authorization.
- Never overwrite existing release assets.
- Never rebuild previously published distributions.
- Never bypass cryptographic provenance verification.
- Never republish an existing PyPI version.
- Verify the exact source commit and release tag.
- Retain all recovery evidence.

## Registry state handling

| PyPI | GitHub assets | Action |
|---|---|---|
| Absent | Absent | Normal release workflow |
| Present | Absent | Authorized GitHub recovery |
| Absent | Present | Block and investigate |
| Present | Present | Verify completeness and consistency |

## Authorized GitHub recovery

1. Identify the original release workflow run.
2. Retrieve its original validated distributions.
3. Verify the artifact inventory and SHA256SUMS.
4. Verify cryptographic provenance.
5. Verify the expected source commit and release tag.
6. Compare distribution hashes against PyPI metadata.
7. Verify the remote tag and GitHub release identity.
8. Confirm existing assets are either absent or identical.
9. Obtain explicit maintainer authorization.
10. Upload only missing, verified release assets.
11. Verify the final GitHub and PyPI artifact hashes.
12. Archive recovery evidence.

## Fail-closed conditions

Stop recovery if any of the following occurs:

- Artifact digest mismatch.
- Missing or invalid provenance.
- Unexpected source commit.
- Changed release tag.
- Unexpected release identity.
- Conflicting existing release asset.
- Unavailable original artifacts.
- Registry API failure.
- Missing maintainer authorization.

## Limitations

GitHub and PyPI publication are separate operations.
Cross-registry publication is not atomic.
Preflight checks cannot eliminate all race conditions.
Recovery must not weaken the normal release security policy.
