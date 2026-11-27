/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import SwiftProtobuf
import XCTest

@testable import Biscuits

final class RevocationIDTests: XCTestCase {
    func testEd25519RevocationIDs() throws {
        let biscuit = try Biscuit(rootKey: Curve25519.Signing.PrivateKey()) {
            Fact("user", 1234)
        }
        XCTAssertEqual(biscuit.authority.revocationIDs, [biscuit.authority.signature])
    }

    func testSecp256r1RevocationIDs() throws {
        let rootKey = P256.Signing.PrivateKey()
        let biscuit = try Biscuit(rootKey: rootKey) {
            Fact("user", 1234)
        }
        let signature = biscuit.authority.signature
        let ids = biscuit.authority.revocationIDs

        // Both forms of the signature
        XCTAssertEqual(ids.count, 2)
        XCTAssert(ids.contains(signature))

        // Swapping in the other form gives a token that still verifies, with the same revocation IDs
        let flippedSignature = try XCTUnwrap(ids.first { $0 != signature })
        var proto = biscuit.proto
        proto.authority.signature = flippedSignature
        let flipped = try Biscuit(serializedData: proto.serializedData(), rootKey: rootKey.publicKey)
        XCTAssertEqual(flipped.authority.signature, flippedSignature)
        XCTAssertEqual(Set(flipped.authority.revocationIDs), Set(ids))

        // Revoking the original signature also revokes the flipped token
        XCTAssertThrowsError(
            try flipped.authorize {
                try Policy.denyIf {
                    Predicate("revocation_id", 0, Term(variable: "id"))
                    try Value.set(from: Set([signature])).contains(Term(variable: "id"))
                }
                Policy.alwaysAllow
            }
        ) { error in
            XCTAssertNotNil((error as? Biscuit.AuthorizationError)?.failedPolicy)
        }
    }
}
