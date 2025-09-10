# A Swift implementation of biscuits

Biscuits is a specification for authorization tokens designed to support decentralized validation
and offline attenuation. This library provides an implementation of biscuits in Swift. In additiona
to specifying a binary representation and cryptographic primitives, Biscuits specifies a Datalog
variant for describing the rights and restrictions on a biscuit.

The complete API documentation for this library can be found at https://swift.biscuitsec.org.
Additional information about biscuits and the Biscuit Project can be found at
https://www.biscuitsec.org.

## Tutorial

The central type of the Biscuits library is the `Biscuit` type, which represents a biscuit token.
Such tokens can be constructed, attenuated, authorized, serialized, deserialized and so on.

The library exposes protocols for valid public and private keys; these protocols are implemented by
the `Curve25519`, `P256` and `SecureEnclave.P256` types from [swift-crypto][swift-crypto]; users may
also add implementations for alternative implementats of ed25519 and secp256r1 if they desire.

The Datalog contents of a biscuit token can be encoded in two ways: either as a string, which will be
parsed at runtime, or using a DSL provided by the library which is type safe and avoids the risk
of injection attacks and syntax errors.

For example:

```swift
import Biscuits
import Crypto
import Foundation

let issuerPrivateKey = Curve25519.Signing.PrivateKey()
// Or, if secp256r1 is more your style...
// let issuerPrivateKey = P256.Signing.PrivateKey()

// Construct a biscuit for a user with specific userID:
let userToken = try Biscuit(rootKey: issuerPrivateKey) {
    Check.checkIf {
        Predicate("user", userID)
    }
    // This is a convenience for defining an expiration check based on the time fact:
    Check.tokenExpires(at: expirationDate)
}
```

In addition to using that biscuit as a bearer token themselves, that user would be able to attenuate
it to give a third party service read-only access to resoures under the `/foo` directory:

```swift
let readOnlyFooToken = try userToken.attenuated() {
    // equivalent to: check if operation("read"), resource($path), $path.starts_with("/foo");
    Check.checkIf {
        Predicate("operation", "read")
        Predicate("resource", Term(variable: "path"))
        Term(variable: "path").startsWith("/foo")
    }
}
```

Finally, the relying party could authorize a request to access the source at "/foo/bar" as that user
using an authorizer like this:

```swift
try readOnlyFooToken.authorize() {
    Fact("user", userID)
    Fact("operation", "read")
    Fact("resource", "/foo/bar")
    Fact("time", Date.now)
}
```

### Datalog DSL

The Datalog DSL has two [resultBuilder][resultBuilder]-based entry points: `DatalogBlock` and
`Authorizer`. `DatalogBlock` is used for constructing and attenuating biscuits, whereas `Authorizer`
is used for authorizing them.

Each contain a series of datalog statements of these types: `Fact`, `Rule`, `Check`, and, in the
case of `Authorizer`, `Policy`. Facts are simple statements, consisting of the name of that fact and
a series of values passed to that fact. Rules, checks, and policies are compound statements
consisting of a series of predicates and expressions.

A `Predicate` is similar to `Fact`, but it can also take variables (which are written
`Term(variable: "name")`), not only literal values. When authorizing the biscuit, these predicates
will be supported by finding facts that match their name and values.

Expressions can be built using a fluent method-based expression builder API, supported on
`Expression`, `Value` and `Term`. For example:

```swift
// equivalent to $foo
let foo = Term(variable: "foo")
// $foo > 0 && $foo < 100
foo.greaterThan(0).and(foo.lessThan(100))
```

## Building and testing

This package is built using Swift 6. Tests are written using XCTest, which is distributed with
xcode.

## License

Licensed under Apache License, Version 2.0, ([LICENSE-APACHE][license] or http://www.apache.org/licenses/LICENSE-2.0)


[swift-crypto]: https://github.com/apple/swift-crypto
[resultBuilder]: https://docs.swift.org/swift-book/documentation/the-swift-programming-language/advancedoperators/#Result-Builders
[license]: ./LICENSE-APACHE
