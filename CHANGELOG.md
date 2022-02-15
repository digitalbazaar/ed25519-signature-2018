# @digitalbazaar/ed25519-signature-2018 Changelog

## 2.1.0 - 2022-02-15

### Added
- Add compatability for 2020 keys.

## 2.0.1 - 2021-04-15

### Fixed
- Make `ed25519-signature-2018-context` a regular dependency.

## 2.0.0 - 2021-04-12

### Changed
- **BREAKING**: Update to `jsonld-signatures` v9 dependency (which removes the
  `verificationMethod` param from suite constructor. It is now strictly
  initialized from `key.id` or `signer.id`. Also increases validation on either
  key or signer/verifier parameters.)
- Enable this suite to enforce compatible contexts on `sign()`.

### Fixed
- Add missing `signer` and `verifier` parameters to the `LinkedDataSignature`
  constructor. This issue caused `this.signer` in subclasses to be `undefined`.

## 1.0.0 - 2021-03-18

### Added
- Initial files extracted from https://github.com/digitalbazaar/jsonld-signatures.
