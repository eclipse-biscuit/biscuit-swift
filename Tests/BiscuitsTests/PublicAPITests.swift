/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import XCTest
import Biscuits

final class PublicAPITests: XCTestCase {
    func testAttenuatingAndAuthorizingABiscuit() throws {
        let userID = 1234;
        let signingKey = Curve25519.Signing.PrivateKey()

        // Create a token for a specific user
        let userToken = try Biscuit(rootKey: signingKey) {
            Fact("user", userID)
        }

        // Create an attenuated token which is only valid for read operations
        let attenuatedReadToken = try userToken.attenuated() {
            Check.checkIf {
                Predicate("operation", "read")
            }
        }

        // Authorize the attenuated token for a read operation (should succeed)
        try attenuatedReadToken.authorize() {
            Fact("operation", "read")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the unattenuated token for a read operation (should succeed)
        try userToken.authorize() {
            Fact("operation", "read")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the unattenuated token for a write operation (should succeed)
        try userToken.authorize() {
            Fact("operation", "write")
            Policy.allowIf {
                Predicate("user", userID)
            }
        }

        // Authorize the attenuated token for a write operation (should fail)
        do {
            try attenuatedReadToken.authorize() {
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
            try attenuatedReadToken.authorize() {
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

        let attenuatedReadToken = try! userToken.attenuated() {
            Check.checkIf {
                Predicate("operation", "read")
            }
        }

        let sealedReadToken = try! attenuatedReadToken.sealed()

        // Sealed tokens may not be attenuated further
        do {
            let _ = try sealedReadToken.attenuated() {
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
            try userToken.authorize() {
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

        try attenuatedToken.authorize() {
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

        try deserializedToken.authorize() {
            Policy.allowIf {
                Predicate("user", userID)
            }
        }
    }
}
