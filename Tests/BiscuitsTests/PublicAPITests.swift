import Biscuits
/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import XCTest

final class PublicAPITests: XCTestCase {
    func testSerializingThirdPartySignedBlocks() throws {
        let issuerPrivateKey = Curve25519.Signing.PrivateKey()
        let attenuationPrivateKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: issuerPrivateKey) {
            Fact("user", 1234)
        }

        let attenuatedToken = try biscuit.attenuated(thirdPartyKey: attenuationPrivateKey) {
            Check.checkIf {
                Predicate("operation", "read")
            }
        }

        let serializedToken = try attenuatedToken.serializedData()

        let deserializedToken = try Biscuit(
            serializedData: serializedToken,
            rootKey: issuerPrivateKey.publicKey
        )

        try deserializedToken.authorize {
            Fact("operation", "read")
            Policy.allowIf {
                Predicate("user", 1234)
            }
        }
    }

    func testAttenuatingAndAuthorizingABiscuit() throws {
        let userID = 1234;
        let signingKey = Curve25519.Signing.PrivateKey()

        // Create a token for a specific user
        let userToken = try Biscuit(rootKey: signingKey) {
            Fact("user", userID)
        }

        // Create an attenuated token which is only valid for read operations
        let attenuatedReadToken = try userToken.attenuated {
            Check.checkIf {
                Predicate("operation", "read")
            }
        }

        // Authorize the attenuated token for a read operation (should succeed)
        try attenuatedReadToken.authorize {
            Fact("operation", "read")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the unattenuated token for a read operation (should succeed)
        try userToken.authorize {
            Fact("operation", "read")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the unattenuated token for a write operation (should succeed)
        try userToken.authorize {
            Fact("operation", "write")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the attenuated token for a write operation (should fail)
        do {
            try attenuatedReadToken.authorize {
                Fact("operation", "write")
                Policy.allowIf {
                    Predicate("user", userID)
                }
            }
            XCTAssert(false)
        } catch let error as Biscuit.AuthorizationError {
            XCTAssertEqual(error.failedCheck?.description, "check if operation(\"read\")")
        }

        // Authorize the attenuated token for a different user (should fail)
        do {
            try attenuatedReadToken.authorize {
                Fact("operation", "read")
                Policy.allowIf {
                    Predicate("user", userID + 1)
                }
            }
            XCTAssert(false)
        } catch let error as Biscuit.AuthorizationError {
            XCTAssert(error.noSuccessfulPolicy)
        }
    }

    func testSealing() {
        let userID = 1234;
        let signingKey = Curve25519.Signing.PrivateKey()

        let userToken = try! Biscuit(rootKey: signingKey) {
            Fact("user", userID)
        }

        let attenuatedReadToken = try! userToken.attenuated {
            Check.checkIf {
                Predicate("operation", "read")
            }
        }

        let sealedReadToken = try! attenuatedReadToken.sealed()

        // Sealed tokens may not be attenuated further
        do {
            let _ = try sealedReadToken.attenuated {
                Fact("group", "admin")
            }
        } catch _ as Biscuit.AttenuationError {
            return
        } catch {
            XCTAssert(false)
        }
        XCTAssert(false)
    }

    func testThirdPartyAttenuation() throws {
        let userID = 1234;
        let signingKey = Curve25519.Signing.PrivateKey()
        let thirdPartyKey = Curve25519.Signing.PrivateKey()
        let thirdPartyPublicKey = thirdPartyKey.publicKey

        let userToken = try Biscuit(rootKey: signingKey) {
            Fact("user", userID)
        }

        let attenuatedToken = try userToken.attenuated(thirdPartyKey: thirdPartyKey) {
            Fact("group", "admin")
        }

        // Authorize both tokens; only the attenuated should succeed because it has the admin group
        // fact signed by the htird party key
        do {
            try userToken.authorize {
                Check.checkIf(trusting: thirdPartyPublicKey) {
                    Predicate("group", "admin")
                }
                Policy.allowIf {
                    Predicate("user", userID)
                }
            }
            XCTAssert(false)
        } catch let error as Biscuit.AuthorizationError {
            XCTAssertEqual(
                error.failedCheck?.description,
                "check if group(\"admin\") trusting \(Biscuit.ThirdPartyKey(key: thirdPartyPublicKey))"
            )
        }

        try attenuatedToken.authorize {
            Check.checkIf(trusting: thirdPartyPublicKey) {
                Predicate("group", "admin")
            }
            Policy.allowIf {
                Predicate("user", userID)
            }
        }
    }

    func testSerializingAndAuthorizingToken() throws {
        let userID = 1234;
        let signingKey = Curve25519.Signing.PrivateKey()

        let userToken = try Biscuit(rootKey: signingKey) {
            Fact("user", userID)
        }

        let serializedToken = try userToken.serializedData()

        let deserializedToken = try Biscuit(
            serializedData: serializedToken,
            rootKey: signingKey.publicKey
        )

        try deserializedToken.authorize {
            Policy.allowIf {
                Predicate("user", userID)
            }
        }
    }

    func testBiscuitQueryValues() throws {
        let signingKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: signingKey) {
            Fact("permission", 1234, "read")
            Fact("permission", 5678, "write")
            try Rule(head: Predicate("permission", Term(variable: "userID"), "read")) {
                Predicate("permission", Term(variable: "userID"), "write")
            }
        }

        let results1 = try biscuit.queryValues(
            result: ("userID", Int.self),
            ("op", String.self)
        ) {
            Predicate("permission", Term(variable: "userID"), Term(variable: "op"))
        }

        XCTAssertEqual(results1.count, 3)
        XCTAssert(results1.contains(where: { $0 == (1234, "read") }))
        XCTAssert(results1.contains(where: { $0 == (5678, "read") }))
        XCTAssert(results1.contains(where: { $0 == (5678, "write") }))

        let results2 = try biscuit.queryValues(result: ("op", String.self)) {
            Predicate("permission", 5678, Term(variable: "op"))
        }

        XCTAssertEqual(results2.count, 2)
        XCTAssert(results2.contains(where: { $0 == "read" }))
        XCTAssert(results2.contains(where: { $0 == "write" }))

        let results3 = try biscuit.queryValues(result: ("userID", Int.self)) {
            Predicate("permission", Term(variable: "userID"), "read")
        }

        XCTAssertEqual(results3.count, 2)
        XCTAssert(results3.contains(where: { $0 == 1234 }))
        XCTAssert(results3.contains(where: { $0 == 5678 }))

        let results4 = try biscuit.queryValues(result: ("op", String.self)) {
            Predicate("permission", 9012, Term(variable: "op"))
        }

        XCTAssertEqual(results4, [])
    }

    func testBiscuitQueryValuesExpectingOne() throws {
        let signingKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: signingKey) {
            Fact("permission", 1234, "read")
            Fact("permission", 5678, "write")
        }

        let (op1) = try biscuit.queryValuesExpectingOne(result: ("op", String.self)) {
            Predicate("permission", 1234, Term(variable: "op"))
        }
        XCTAssertEqual(op1, "read")

        let (op2) = try biscuit.queryValuesExpectingOne(result: ("op", String.self)) {
            Predicate("permission", 5678, Term(variable: "op"))
        }
        XCTAssertEqual(op2, "write")

        let (userID) = try biscuit.queryValuesExpectingOne(result: ("userID", Int.self)) {
            Predicate("permission", Term(variable: "userID"), "write")
        }
        XCTAssertEqual(userID, 5678)
    }

    func testAuthorizationQueryValues() throws {
        let signingKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: signingKey) {
            Fact("permission", 1234, "read")
            Fact("permission", 5678, "write")
        }

        let auth = try biscuit.authorize {
            Fact("user", 5678)
            try Rule(head: Predicate("permission", Term(variable: "userID"), "read")) {
                Predicate("permission", Term(variable: "userID"), "write")
            }
            Policy.allowIf {
                Predicate("user", Term(variable: "userID"))
                Predicate("permission", Term(variable: "userID"), "read")
            }
        }

        let results1 = try auth.queryValues(
            result: ("userID", Int.self),
            ("op", String.self)
        ) {
            Predicate("permission", Term(variable: "userID"), Term(variable: "op"))
        }

        XCTAssertEqual(results1.count, 3)
        XCTAssert(results1.contains(where: { $0 == (1234, "read") }))
        XCTAssert(results1.contains(where: { $0 == (5678, "read") }))
        XCTAssert(results1.contains(where: { $0 == (5678, "write") }))

        let results2 = try auth.queryValues(result: ("op", String.self)) {
            Predicate("permission", 5678, Term(variable: "op"))
        }

        XCTAssertEqual(results2.count, 2)
        XCTAssert(results2.contains(where: { $0 == "read" }))
        XCTAssert(results2.contains(where: { $0 == "write" }))

        let results3 = try auth.queryValues(result: ("userID", Int.self)) {
            Predicate("permission", Term(variable: "userID"), "read")
        }

        XCTAssertEqual(results3.count, 2)
        XCTAssert(results3.contains(where: { $0 == 1234 }))
        XCTAssert(results3.contains(where: { $0 == 5678 }))

        let results4 = try auth.queryValues(result: ("op", String.self)) {
            Predicate("permission", 9012, Term(variable: "op"))
        }

        XCTAssertEqual(results4, [])
    }

    func testAuthorizationQueryValuesExpectingOne() throws {
        let signingKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: signingKey) {
            Fact("permission", 1234, "read")
            Fact("permission", 5678, "write")
        }

        let auth = try biscuit.authorize {
            Fact("user", 1234)
            try Rule(head: Predicate("permission", Term(variable: "userID"), "read")) {
                Predicate("permission", Term(variable: "userID"), "write")
            }
            Policy.allowIf {
                Predicate("user", Term(variable: "userID"))
                Predicate("permission", Term(variable: "userID"), "read")
            }
        }

        let (userID) = try auth.queryValuesExpectingOne(result: ("userID", Int.self)) {
            Predicate("user", Term(variable: "userID"))
        }
        XCTAssertEqual(userID, 1234)

        let (op) = try auth.queryValuesExpectingOne(result: ("op", String.self)) {
            Predicate("user", Term(variable: "userID"))
            Predicate("permission", Term(variable: "userID"), Term(variable: "op"))
        }
        XCTAssertEqual(op, "read")
    }

    func testQueryValuesWithTrustedScopes() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let thirdPartyKey = Curve25519.Signing.PrivateKey()

        let biscuit = try Biscuit(rootKey: signingKey) {
            Fact("user", 1234)
        }

        let attenuatedToken = try biscuit.attenuated(thirdPartyKey: thirdPartyKey) {
            Fact("permission", "read")
        }

        let results1 = try attenuatedToken.queryValues(result: ("op", String.self)) {
            Predicate("permission", Term(variable: "op"))
        }
        XCTAssertEqual(results1, [])

        let results2 = try attenuatedToken.queryValues(
            result: ("op", String.self),
            trusting: thirdPartyKey.publicKey
        ) {
            Predicate("permission", Term(variable: "op"))
        }
        XCTAssertEqual(results2, [("read")])
    }
}
