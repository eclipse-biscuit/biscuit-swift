/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import XCTest

@testable import Biscuits

final class DeserializationLimitsTests: XCTestCase {
    let rootKey = Curve25519.Signing.PrivateKey()

    // Every setting must be at its most restrictive value in allowNothing, including settings added
    // in the future, so this checks each stored property by reflection rather than by name
    func testAllowNothingAllowsNothing() {
        assertAllowsNothing(Biscuit.DeserializationLimits.allowNothing, path: "allowNothing")
    }

    func testPerBlockAllowNothingAllowsNothing() {
        assertAllowsNothing(Biscuit.DeserializationLimits.PerBlock.allowNothing, path: "PerBlock.allowNothing")
    }

    // Every setting must have an enforcement test below, including settings added in the future
    func testEveryTokenLimitIsTested() {
        assertTested(
            Biscuit.DeserializationLimits(),
            by: self.tokenLimitCases.map(\.property),
            ignoring: ["authority", "attenuations"]
        )
    }

    func testEveryBlockLimitIsTested() {
        assertTested(Biscuit.DeserializationLimits.PerBlock(), by: self.blockLimitCases.map(\.property))
    }

    func testTokenLimitsAreEnforced() throws {
        for limitCase in self.tokenLimitCases {
            let token = try limitCase.token()
            self.assertAccepted(
                token,
                .allowEverything,
                verifyingSignatures: limitCase.hasValidSignatures,
                "\(limitCase.property): token should be accepted without limits"
            )
            var limits = Biscuit.DeserializationLimits.allowEverything
            limitCase.restrict(&limits)
            self.assertRejected(token, limits, limitCase.expectedError, limitCase.property)
        }
    }

    // Each block limit is checked with the restricted feature in the authority block and in an
    // attenuation, and must only apply to the block it was set for
    func testBlockLimitsAreEnforced() throws {
        for limitCase in self.blockLimitCases {
            let block = try limitCase.block()
            let inAuthority = try Biscuit(authorityBlock: block, rootKey: self.rootKey).serializedData()
            let inAttenuation = try Biscuit(authorityBlock: Biscuit.DatalogBlock(""), rootKey: self.rootKey)
                .attenuated(using: block)
                .serializedData()
            let property = limitCase.property

            self.assertAccepted(inAuthority, .allowEverything, "\(property): authority block should be accepted")
            self.assertAccepted(inAttenuation, .allowEverything, "\(property): attenuation should be accepted")

            var authorityLimits = Biscuit.DeserializationLimits.allowEverything
            limitCase.restrict(&authorityLimits.authority)
            self.assertRejected(inAuthority, authorityLimits, limitCase.expectedError, "authority.\(property)")
            self.assertAccepted(
                inAttenuation,
                authorityLimits,
                "authority.\(property) should not apply to attenuations"
            )

            var attenuationLimits = Biscuit.DeserializationLimits.allowEverything
            limitCase.restrict(&attenuationLimits.attenuations)
            self.assertRejected(inAttenuation, attenuationLimits, limitCase.expectedError, "attenuations.\(property)")
            self.assertAccepted(
                inAuthority,
                attenuationLimits,
                "attenuations.\(property) should not apply to the authority block"
            )
        }
    }

    struct TokenLimitCase {
        let property: String
        let restrict: (inout Biscuit.DeserializationLimits) -> Void
        let expectedError: Biscuit.DeserializationLimitError
        let token: () throws -> Data
        // Tokens built by editing their protobuf don't have valid signatures, so they can only be
        // accepted without verification
        var hasValidSignatures = true
    }

    struct BlockLimitCase {
        let property: String
        let restrict: (inout Biscuit.DeserializationLimits.PerBlock) -> Void
        let expectedError: Biscuit.DeserializationLimitError
        let block: () throws -> Biscuit.DatalogBlock
    }

    var tokenLimitCases: [TokenLimitCase] {
        let rootKey = self.rootKey
        let biscuit = { try Biscuit(authorityBlock: "fact(1);", rootKey: rootKey) }
        return [
            TokenLimitCase(
                property: "allowAttenuationsWithExternalSignatures",
                restrict: { $0.allowAttenuationsWithExternalSignatures = false },
                expectedError: .attenuationsWithExternalSignaturesNotAllowed,
                token: {
                    try biscuit()
                        .attenuated(using: "check if true;", thirdPartyKey: Curve25519.Signing.PrivateKey())
                        .serializedData()
                }
            ),
            TokenLimitCase(
                property: "allowAttenuationsWithoutExternalSignatures",
                restrict: { $0.allowAttenuationsWithoutExternalSignatures = false },
                expectedError: .attenuationsWithoutExternalSignaturesNotAllowed,
                token: { try biscuit().attenuated(using: "check if true;").serializedData() }
            ),
            TokenLimitCase(
                property: "allowSealedTokens",
                restrict: { $0.allowSealedTokens = false },
                expectedError: .sealedTokensNotAllowed,
                token: { try biscuit().sealed().serializedData() }
            ),
            TokenLimitCase(
                property: "allowUnsealedTokens",
                restrict: { $0.allowUnsealedTokens = false },
                expectedError: .unsealedTokensNotAllowed,
                token: { try biscuit().serializedData() }
            ),
            TokenLimitCase(
                property: "maximumTokenSize",
                restrict: { $0.maximumTokenSize = 10 },
                expectedError: .tokenTooLarge,
                token: { try biscuit().serializedData() }
            ),
            TokenLimitCase(
                property: "maximumBlocks",
                restrict: { $0.maximumBlocks = 1 },
                expectedError: .tooManyBlocks,
                token: { try biscuit().attenuated(using: "check if true;").serializedData() }
            ),
            TokenLimitCase(
                property: "minimumSignatureVersion",
                restrict: { $0.minimumSignatureVersion = 1 },
                expectedError: .signatureVersionTooLow,
                token: {
                    // This library only creates version 1 signatures, so mark the authority block as
                    // version 0; this invalidates its signature
                    var proto = try Biscuit_Format_Schema_Biscuit(serializedBytes: biscuit().serializedData())
                    proto.authority.clearVersion()
                    return try proto.serializedData()
                },
                hasValidSignatures: false
            ),
            TokenLimitCase(
                property: "allowedInternalSigningAlgorithms",
                restrict: { $0.allowedInternalSigningAlgorithms = [.secp256r1] },
                expectedError: .internalSigningAlgorithmNotAllowed,
                token: { try biscuit().serializedData() }
            ),
            TokenLimitCase(
                property: "allowedExternalSigningAlgorithms",
                restrict: { $0.allowedExternalSigningAlgorithms = [.secp256r1] },
                expectedError: .externalSigningAlgorithmNotAllowed,
                token: {
                    try biscuit()
                        .attenuated(using: "check if true;", thirdPartyKey: Curve25519.Signing.PrivateKey())
                        .serializedData()
                }
            ),
        ]
    }

    var blockLimitCases: [BlockLimitCase] {
        let datalog = { (datalog: String) in { try Biscuit.DatalogBlock(datalog) } }
        let trustedKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
            .map { String(format: "%02hhx", $0) }
            .joined()
        return [
            BlockLimitCase(
                property: "allowClosures",
                restrict: { $0.allowClosures = false },
                expectedError: .closuresNotAllowed,
                block: datalog("check if [1].any($x -> $x == 1);")
            ),
            BlockLimitCase(
                property: "maximumBlockSize",
                restrict: { $0.maximumBlockSize = 10 },
                expectedError: .blockTooLarge,
                block: datalog("check if claim(\"YELLOW SUBMARINE\");")
            ),
            BlockLimitCase(
                property: "maximumFacts",
                restrict: { $0.maximumFacts = 0 },
                expectedError: .tooManyFacts,
                block: datalog("fact(1);")
            ),
            BlockLimitCase(
                property: "maximumRules",
                restrict: { $0.maximumRules = 0 },
                expectedError: .tooManyRules,
                block: datalog("derived($x) <- fact($x);")
            ),
            BlockLimitCase(
                property: "maximumChecks",
                restrict: { $0.maximumChecks = 0 },
                expectedError: .tooManyChecks,
                block: datalog("check if true;")
            ),
            BlockLimitCase(
                property: "maximumSymbols",
                restrict: { $0.maximumSymbols = 0 },
                expectedError: .tooManySymbols,
                block: datalog("fact(\"symbol\");")
            ),
            BlockLimitCase(
                property: "maximumPublicKeys",
                restrict: { $0.maximumPublicKeys = 0 },
                expectedError: .tooManyPublicKeys,
                block: datalog("check if true trusting ed25519/\(trustedKey);")
            ),
            BlockLimitCase(
                property: "maximumContextLength",
                restrict: { $0.maximumContextLength = 2 },
                expectedError: .contextTooLong,
                block: { try Biscuit.DatalogBlock("fact(1);", context: "context") }
            ),
            BlockLimitCase(
                property: "maximumQueriesPerCheck",
                restrict: { $0.maximumQueriesPerCheck = 1 },
                expectedError: .tooManyQueries,
                block: datalog("check if true or false;")
            ),
            BlockLimitCase(
                property: "maximumPredicatesPerBody",
                restrict: { $0.maximumPredicatesPerBody = 0 },
                expectedError: .tooManyPredicates,
                block: datalog("check if fact(1);")
            ),
            BlockLimitCase(
                property: "maximumExpressionsPerBody",
                restrict: { $0.maximumExpressionsPerBody = 0 },
                expectedError: .tooManyExpressions,
                block: datalog("check if true;")
            ),
            BlockLimitCase(
                property: "maximumOpsPerExpression",
                restrict: { $0.maximumOpsPerExpression = 2 },
                expectedError: .tooManyOps,
                block: datalog("check if 1 == 1;")
            ),
            BlockLimitCase(
                property: "maximumTermsPerPredicate",
                restrict: { $0.maximumTermsPerPredicate = 0 },
                expectedError: .tooManyTerms,
                block: datalog("fact(1);")
            ),
            BlockLimitCase(
                property: "maximumNameLength",
                restrict: { $0.maximumNameLength = 3 },
                expectedError: .nameTooLong,
                block: datalog("longname(1);")
            ),
            BlockLimitCase(
                property: "maximumBytesLength",
                restrict: { $0.maximumBytesLength = 0 },
                expectedError: .bytesTooLong,
                block: datalog("fact(hex:00);")
            ),
            BlockLimitCase(
                property: "maximumStringLength",
                restrict: { $0.maximumStringLength = 0 },
                expectedError: .stringTooLong,
                block: datalog("fact(\"a\");")
            ),
            BlockLimitCase(
                property: "maximumSetLength",
                restrict: { $0.maximumSetLength = 0 },
                expectedError: .setTooLong,
                block: datalog("fact({1});")
            ),
            BlockLimitCase(
                property: "maximumArrayLength",
                restrict: { $0.maximumArrayLength = 0 },
                expectedError: .arrayTooLong,
                block: datalog("fact([1]);")
            ),
            BlockLimitCase(
                property: "maximumMapLength",
                restrict: { $0.maximumMapLength = 0 },
                expectedError: .mapTooLong,
                block: datalog("fact({\"key\": 1});")
            ),
            BlockLimitCase(
                property: "allowedBinaryOperations",
                restrict: { $0.allowedBinaryOperations = [] },
                expectedError: .binaryOperationNotAllowed,
                block: datalog("check if 1 == 1;")
            ),
            BlockLimitCase(
                property: "allowedUnaryOperations",
                restrict: { $0.allowedUnaryOperations = [] },
                expectedError: .unaryOperationNotAllowed,
                block: datalog("check if !false;")
            ),
            BlockLimitCase(
                property: "allowedUnaryExternalFunctions",
                restrict: { $0.allowedUnaryExternalFunctions = [] },
                expectedError: .externalFunctionNotAllowed,
                // Datalog has no syntax for calling foreign functions, so build the expression directly
                block: {
                    let call = Expression(op: OpUnary.ffi("function"), expr: Expression(term: Term(value: 1)))
                    return Biscuit.DatalogBlock { Check.checkIf { call } }
                }
            ),
            BlockLimitCase(
                property: "allowedBinaryExternalFunctions",
                restrict: { $0.allowedBinaryExternalFunctions = [] },
                expectedError: .externalFunctionNotAllowed,
                block: {
                    let call = Expression(
                        op: OpBinary.ffi("function"),
                        lhs: Expression(term: Term(value: 1)),
                        rhs: Expression(term: Term(value: 2))
                    )
                    return Biscuit.DatalogBlock { Check.checkIf { call } }
                }
            ),
            BlockLimitCase(
                property: "allowedTermTypes",
                restrict: { $0.allowedTermTypes = [] },
                expectedError: .termTypeNotAllowed,
                block: datalog("fact(1);")
            ),
            BlockLimitCase(
                property: "allowedMapKeyTypes",
                restrict: { $0.allowedMapKeyTypes = [] },
                expectedError: .mapKeyTypeNotAllowed,
                block: datalog("fact({\"key\": 1});")
            ),
            BlockLimitCase(
                property: "allowedTrustedScopes",
                restrict: { $0.allowedTrustedScopes = [] },
                expectedError: .trustedScopeNotAllowed,
                block: datalog("check if true trusting previous;")
            ),
            BlockLimitCase(
                property: "allowedCheckKinds",
                restrict: { $0.allowedCheckKinds = [] },
                expectedError: .checkKindNotAllowed,
                block: datalog("check if true;")
            ),
        ]
    }

    private func deserialize(_ token: Data, _ limits: Biscuit.DeserializationLimits, verified: Bool) throws {
        if verified {
            _ = try Biscuit(serializedData: token, rootKey: self.rootKey.publicKey, limitedBy: limits)
        } else {
            _ = try UnverifiedBiscuit(serializedData: token, limitedBy: limits)
        }
    }

    private func assertAccepted(
        _ token: Data,
        _ limits: Biscuit.DeserializationLimits,
        verifyingSignatures: Bool = true,
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for verified in verifyingSignatures ? [true, false] : [false] {
            XCTAssertNoThrow(
                try self.deserialize(token, limits, verified: verified),
                "\(message) (\(verified ? "Biscuit" : "UnverifiedBiscuit"))",
                file: file,
                line: line
            )
        }
    }

    private func assertRejected(
        _ token: Data,
        _ limits: Biscuit.DeserializationLimits,
        _ expectedError: Biscuit.DeserializationLimitError,
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for verified in [true, false] {
            let message = "\(message) (\(verified ? "Biscuit" : "UnverifiedBiscuit"))"
            XCTAssertThrowsError(
                try self.deserialize(token, limits, verified: verified),
                message,
                file: file,
                line: line
            ) {
                XCTAssertEqual($0 as? Biscuit.DeserializationLimitError, expectedError, message, file: file, line: line)
            }
        }
    }

    private func assertTested(_ limits: Any, by testedProperties: [String], ignoring: Set<String> = []) {
        let properties = Set(Mirror(reflecting: limits).children.compactMap(\.label)).subtracting(ignoring)
        let tested = Set(testedProperties)
        XCTAssertEqual(testedProperties.count, tested.count, "a property is tested more than once")
        XCTAssertEqual(properties.subtracting(tested), [], "these properties have no enforcement test")
        XCTAssertEqual(tested.subtracting(properties), [], "these tested properties don't exist")
    }

    private func assertAllowsNothing(_ value: Any, path: String) {
        let children = Mirror(reflecting: value).children
        XCTAssertFalse(children.isEmpty, "\(path) has no fields to check")
        for child in children {
            let label = child.label ?? "?"
            let path = "\(path).\(label)"
            let mirror = Mirror(reflecting: child.value)
            switch child.value {
            case let flag as Bool:
                XCTAssertFalse(flag, "\(path) should be false")
            case let limit as Int where label == "minimumSignatureVersion":
                XCTAssertEqual(limit, 1, "\(path) should be the highest supported version")
            case let limit as Int:
                XCTAssertEqual(limit, 0, "\(path) should be 0")
            case _ where mirror.displayStyle == .optional:
                // Every optional setting is a set, where nil would allow anything
                guard let set = mirror.children.first?.value else {
                    XCTFail("\(path) should be an empty set, not nil")
                    continue
                }
                let setMirror = Mirror(reflecting: set)
                XCTAssertEqual(setMirror.displayStyle, .set, "\(path) is an unexpected optional type")
                XCTAssertTrue(setMirror.children.isEmpty, "\(path) should be empty")
            case _ where mirror.displayStyle == .struct:
                assertAllowsNothing(child.value, path: path)
            default:
                XCTFail("\(path) has a type this test doesn't know how to check")
            }
        }
    }
}
