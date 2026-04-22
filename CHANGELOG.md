# `2.0.1`

- Fix bug in base64url encoding/decoding: now accept base64url data with or without padding bytes
  and emit data without padding bytes (previously always required padding bytes)

# `2.0.0`

- Fix platform minimum versions being too low for iOS, tvOS, and watchOS
- Declare support for visionOS
- Declare support for SwiftCrypto version 4.0.0
- Fix potential issue with non-canonical Datalog serialization
- Fix `UnverifiedBiscuit` verification method not verifying final proof
- Remove context argument from APIs that would let user set context in conflicting ways

# `1.1.1`

- Fix `secp256r1` signatures (#15)

# `1.1.0`

- Additional operations on `UnverifiedBiscuit` (#13)
  - Parse from base64Url
  - Attenuate (including with third-party blocks)
  - Seal 

# `1.0.0`

Initial release with support for biscuit v3.3
