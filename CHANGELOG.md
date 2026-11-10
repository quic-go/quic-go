# Changelog

## [Unreleased]

### Fixed

- Require renewed path validation before migration after 30 seconds without
  received packets on the path.
- Discard queued probes from completed path validation to prevent delayed
  responses from revalidating an expired path.
