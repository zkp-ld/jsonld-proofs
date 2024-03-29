# Changelog

## [0.11.2] - 2024-03-18

### Changed

- Upgraded dependencies
- Added a negative test for deriveProof without VCs nor PPID

## [0.11.1] - 2024-03-18

### Changed

- Upgraded dependencies
- Added a test for deriving and verifying VP without VCs

### Fixed

- Rename a variable to conform to naming rules

## [0.11.0] - 2024-03-15

### Fixed

- Remove `"type": "module"` from `package.json` to resolve inconsistency with CJS usage. (This package is intended to be used as a CommonJS module. However, the presence of `"type": "module"` in `package.json` was misleading and could cause issues in environments expecting CJS modules. This change ensures compatibility and clarity by removing the inconsistent module type specification.)

### Changed

- Upgrade dependencies

## [0.10.1] - 2024-01-11

### Changed

- Upgraded dependencies

## [0.10.0] - 2023-11-27

### Added

- Several functions now include comments (assisted by GitHub Copilot)

### Fixed

- Update tests to resolve errors with vitest/jest

### Changed

- Rename and add several types, e.g., `VcPair` to `VCPair`
- Refactor internal processing (assisted by GitHub Copilot)
- Remove unused dependencies
- Update ESLint configurations

## [0.9.0] - 2023-10-18

### Added

- Reflect the latest updates in `rdf-proofs-wasm` (and its underlying `rdf-proofs`)
  - Add predicate proofs generation and verification

### Changed

- Interfaces of `deriveProof` and `verifyProof`
- Upgrade dependencies

## [0.8.2] - 2023-10-02

### Fixed

- Reflect the latest updates in `rdf-proofs-wasm` (and its underlying `rdf-proofs`)
  - Change `proofPurpose` of VP from `assertionMethod` to `authentication` to align with the spec
- Fix context URL for schema.org in tests to add the trailing slash

## [0.8.1] - 2023-09-29

### Fixed

- Enable selective disclosure for `@set` and `@list`
  - now you can just remove elements in `@set`, whereas use a bnode id like `_:abc` to unreveal an element in `@list`

## [0.8.0] - 2023-09-28

### Added

- Reflect the latest updates in `rdf-proofs-wasm` (and its underlying `rdf-proofs`)
  - Blind signing feature
  - PPID feature
  - `domain` parameter to `deriveProof` and `verifyProof`
  - Allow inclusion of committed secrets in VP, generated by `derivedProof`, for using VP as an issuance request for bound VC
  - Set current datetime for `created` if not provided

### Changed

- Rename `nonce` to `challenge`
- Upgrade dependencies: nanoid 5.0.1, etc.
