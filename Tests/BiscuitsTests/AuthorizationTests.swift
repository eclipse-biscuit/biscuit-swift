/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import SwiftProtobuf
import XCTest
@testable import Biscuits

final class AuthorizationTests: XCTestCase {
    let rootPublicKey: Curve25519.Signing.PublicKey = try! Curve25519.Signing.PublicKey(
        rawRepresentation: hexDecode("1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284")!
    )

    let rootPrivateKey: Curve25519.Signing.PrivateKey = try! Curve25519.Signing.PrivateKey(
        rawRepresentation: hexDecode("99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61")!
    )

    func loadBiscuit(from resource: String) throws -> Biscuit {
        let biscuitPath = Bundle.module.path(forResource: resource, ofType: "bc")!
        let biscuitData = try! Data(contentsOf: URL(fileURLWithPath: biscuitPath), options: .mappedIfSafe)
        return try Biscuit(serializedData: biscuitData) { _ in self.rootPublicKey }
    }

    func testBasicToken() throws {
        let biscuit = try self.loadBiscuit(from: "test001_basic")
        do {
            try biscuit.authorize(using: """
                resource("file1");
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if resource($0), operation(\"read\"), right($0, \"read\");"))
            return
        }
        XCTAssert(false)
    }

    func testBasicTokenDSL() throws {
        let biscuit = try self.loadBiscuit(from: "test001_basic")
        do {
            try biscuit.authorize() {
                Fact("resource", "file1")
                Policy.alwaysAllow
            }
        } catch let err as Biscuit.AuthorizationError {
            XCTAssertEqual(err.failedCheck, Check.checkIf {
                Predicate("resource", Term(variable: "0"))
                Predicate("operation", "read")
                Predicate("right", Term(variable: "0"), "read")
            })
            return
        }
        XCTAssert(false)
    }

    func testDifferentRootKey() throws {
        do {
            let _ = try self.loadBiscuit(from: "test002_different_root_key")
        } catch let error as Biscuit.ValidationError where error == Biscuit.ValidationError.invalidSignature {
            return
        }
        XCTAssert(false)
    }

    func testInvalidSignatureFormat() throws {
        do {
            let _ = try self.loadBiscuit(from: "test003_invalid_signature_format")
        } catch let error as Biscuit.ValidationError where error == Biscuit.ValidationError.invalidSignature {
            return
        }
        XCTAssert(false)
    }

    func testRandomBlock() throws {
        do {
            let _ = try self.loadBiscuit(from: "test004_random_block")
        } catch SwiftProtobuf.BinaryDecodingError.malformedProtobuf {
            return
        }
        XCTAssert(false)
    }

    func testInvalidSignature() throws {
        do {
            let _ = try self.loadBiscuit(from: "test005_invalid_signature")
        } catch let error as Biscuit.ValidationError where error == Biscuit.ValidationError.invalidSignature {
            return
        }
        XCTAssert(false)
    }

    func testReorderedBlocks() throws {
        do {
            let _ = try self.loadBiscuit(from: "test006_reordered_blocks")
        } catch let error as Biscuit.ValidationError where error == Biscuit.ValidationError.invalidSignature {
            return
        }
        XCTAssert(false)
    }

    func testScopedRules() throws {
        let biscuit = try self.loadBiscuit(from: "test007_scoped_rules")
        do {
            try biscuit.authorize(using: """
                resource("file2");
                operation("read");
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if resource($0), operation(\"read\"), right($0, \"read\");"))
            return
        }
        XCTAssert(false)
    }

    func testScopedChecks() throws {
        let biscuit = try self.loadBiscuit(from: "test008_scoped_checks")
        do {
            try biscuit.authorize(using: """
                resource("file2");
                operation("read");
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if resource($0), operation(\"read\"), right($0, \"read\");"))
            return
        }
        XCTAssert(false)
    }

    func testExpiredToken() throws {
        let biscuit = try self.loadBiscuit(from: "test009_expired_token")
        do {
            try biscuit.authorize(using: """
                resource("file1");
                operation("read");
                time(2020-12-21T09:23:12Z);
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if time($time), $time <= 2018-12-20T00:00:00Z;"))
            return
        }
        XCTAssert(false)
    }

    func testAuthorizerScope() throws {
        let biscuit = try self.loadBiscuit(from: "test010_authorizer_scope")
        do {
            try biscuit.authorize(using: """
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if right($0, $1), resource($0), operation($1);"))
            return
        }
        XCTAssert(false)
    }

    func testAuthorizerAuthorityChecks() throws {
        let biscuit = try self.loadBiscuit(from: "test011_authorizer_authority_caveats")
        do {
            try biscuit.authorize(using: """
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true;
            """)
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if right($0, $1), resource($0), operation($1);"))
            return
        }
        XCTAssert(false)
    }

    func testAuthorityChecks() throws {
        let biscuit = try self.loadBiscuit(from: "test012_authority_caveats")
        do {
            try biscuit.authorize(using: """
                resource("file2");
                operation("read");
                allow if true;
            """)
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }

    func testBlockRules() throws {
        let biscuit = try self.loadBiscuit(from: "test013_block_rules")
        try biscuit.authorize(using: """
            resource("file1");
            time(2020-12-21T09:23:12Z);
            allow if true;
        """)
        do {
            try biscuit.authorize(using: """
                resource("file2");
                time(2020-12-21T09:23:12Z);
                allow if true;
            """)
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)

    }

    func testRegexConstraint() throws {
        let biscuit = try self.loadBiscuit(from: "test014_regex_constraint")
        try biscuit.authorize(using: """
            resource("file123.txt");
            allow if true;
        """)
        do {
            try biscuit.authorize(using: """
                resource("file1");
                allow if true;
            """)
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }

    func testMultiQueriesCaveats() throws {
        let biscuit = try self.loadBiscuit(from: "test015_multi_queries_caveats")
        try biscuit.authorize(using: """
            check if must_be_present($0) or must_be_present($0);
            allow if true;
        """)
    }

    func testIndependentCheckHeadName() throws {
        let biscuit = try self.loadBiscuit(from: "test016_caveat_head_name")
        do {
            try biscuit.authorize(using: "allow if true;")
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }

    func testExpressionSyntax() throws {
        let biscuit = try self.loadBiscuit(from: "test017_expressions")
        try biscuit.authorize(using: "allow if true;")
    }

    func testUnboundVariables() throws {
        do {
            let biscuit = try self.loadBiscuit(from: "test018_unbound_variables_in_rule")
            let _ = try biscuit.authorize(using: "allow if true;")
        } catch let error as Biscuit.ValidationError where error == Biscuit.ValidationError.unboundVariableInHead {
            return
        }
        XCTAssert(false)
    }

    func testAmbientSymbol() throws {
        let biscuit = try self.loadBiscuit(from: "test019_generating_ambient_from_variables")
        do {
            try biscuit.authorize(using: "allow if true;")
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }

    func testSealed() throws {
        let biscuit = try self.loadBiscuit(from: "test020_sealed")
        try biscuit.authorize(using: """
            resource("file1");
            operation("read");
            allow if true;
        """)
    }

    func testParsing() throws {
        let biscuit = try self.loadBiscuit(from: "test021_parsing")
        try biscuit.authorize(using: """
            check if ns::fact_123("hello é\t😁");
            allow if true;
        """)
    }

    func testDefaultSymbols() throws {
        let biscuit = try self.loadBiscuit(from: "test022_default_symbols")
        try biscuit.authorize(using: """
            check if read(0), write(1), resource(2), operation(3), right(4), time(5),
                     role(6), owner(7), tenant(8), namespace(9), user(10), team(11),
                     service(12), admin(13), email(14), group(15), member(16), ip_address(17),
                     client(18), client_ip(19), domain(20), path(21), version(22), cluster(23),
                     node(24), hostname(25), nonce(26), query(27);
            allow if true;
        """)
    }

    func testExecutionScope() throws {
        let biscuit = try self.loadBiscuit(from: "test023_execution_scope")
        do {
            try biscuit.authorize(using: "allow if true;")
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }
    
    func testThirdParty() throws {
        let biscuit = try self.loadBiscuit(from: "test024_third_party")
        try biscuit.authorize(using: "allow if true;")
    }

    func testCheckAll() throws {
        let biscuit = try self.loadBiscuit(from: "test025_check_all")
        try biscuit.authorize(using: """
            operation("A");
            operation("B");
            allow if true;
        """)
        do {
            try biscuit.authorize(using: """
                operation("A");
                operation("invalid");
                allow if true;
            """)
        } catch _ as Biscuit.AuthorizationError {
            return
        }
        XCTAssert(false)
    }

    func testPublicKeysInterning() throws {
        let biscuit = try self.loadBiscuit(from: "test026_public_keys_interning")
        try biscuit.authorize(using: """
            check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;

            deny if query(3);
            deny if query(1, 2);
            deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
            allow if true;
        """)
    }

    func testIntegerWraparound() throws {
        let biscuit = try self.loadBiscuit(from: "test027_integer_wraparound")
        do {
            let _ = try biscuit.authorize(using: "allow if true;")
        } catch let error as Biscuit.EvaluationError where error == Biscuit.EvaluationError.integerOverflow {
            return
        }
        XCTAssert(false)
    }

    func testExpressionsV4() throws {
        let biscuit = try self.loadBiscuit(from: "test028_expressions_v4")
        try biscuit.authorize(using: "allow if true;")
    }

    func testRejectIf() throws {
        let biscuit = try self.loadBiscuit(from: "test029_reject_if")
        try biscuit.authorize(using: "allow if true; test(false);")
        do {
            try biscuit.authorize(using: "allow if true; test(true);")
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("reject if test($test), $test;"))
            return
        }
        XCTAssert(false)
    }

    func testNull() throws {
        let biscuit = try self.loadBiscuit(from: "test030_null")
        try biscuit.authorize(using: "allow if true; fact(null, null);")
        do {
            try biscuit.authorize(using: "allow if true; fact(null, 1);")
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if fact(null, $value), $value == null;"))
            return
        }
        XCTAssert(false)
    }

    func testHeterogeneousEqual() throws {
        let biscuit = try self.loadBiscuit(from: "test031_heterogeneous_equal")
        try biscuit.authorize(using: "fact(1, 1); fact2(1, 2); allow if true;")
        do {
            try biscuit.authorize(using: "fact(1, 2); fact2(1, 1); allow if true;")
        } catch let err as Biscuit.AuthorizationError {
            try XCTAssertEqual(err.failedCheck, Check("check if fact(1, $value), 1 == $value;"))
            return
        }
        XCTAssert(false)
    }

    func testLazinessClosures() throws {
        let biscuit = try self.loadBiscuit(from: "test032_laziness_closures")
        try biscuit.authorize() { Policy.alwaysAllow }
        do {
            try biscuit.authorize(using: "allow if [true].any($p -> [true].all($p -> $p));")
        } catch let err as Biscuit.EvaluationError where err == Biscuit.EvaluationError.variableShadowing {
            return
        }
        XCTAssert(false)
    }

    func testTypeOf() throws {
        let biscuit = try self.loadBiscuit(from: "test033_typeof")
        try biscuit.authorize() { Policy.alwaysAllow }
    }

    func testArrayMap() throws {
        let biscuit = try self.loadBiscuit(from: "test034_array_map")
        try biscuit.authorize() { Policy.alwaysAllow }
    }

    func testFfiUnspecified() throws {
        let biscuit = try self.loadBiscuit(from: "test035_ffi")
        do {
            try biscuit.authorize(using: "allow if true;")
        } catch let err as Biscuit.EvaluationError {
            XCTAssertEqual(err, Biscuit.EvaluationError.unknownForeignFunction("test"))
            return
        }
        XCTAssert(false)
    }

    func testSecP256R1() throws {
        let biscuit = try self.loadBiscuit(from: "test036_secp256r1")
        try biscuit.authorize() {
            Fact("resource", "file1")
            Fact("operation", "read")
            Policy.alwaysAllow
        }
    }

    func testSecP256R1ThirdParty() throws {
        let biscuit = try self.loadBiscuit(from: "test037_secp256r1_third_party")
        try biscuit.authorize() {
            Fact("resource", "file1")
            Fact("operation", "read")
            Policy.alwaysAllow
        }
    }

    func testTryOp() throws {
        let biscuit = try self.loadBiscuit(from: "test038_try_op")
        try biscuit.authorize() { Policy.alwaysAllow }
        do {
            try biscuit.authorize(using: "check if true.try_or(true === 12); allow if true;")
        } catch let err as Biscuit.EvaluationError where err == Biscuit.EvaluationError.typeError {
            return
        }
        XCTAssert(false)
    }
}

func hexDecode(_ string: String) -> Data? {
    if string.count % 2 != 0 || string.count == 0 {
        return nil
    }

    let stringBytes = Array(string.data(using: String.Encoding.utf8)!)
    var bytes = Data()

    for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
        let char1 = stringBytes[i]
        let char2 = stringBytes[i + 1]

        bytes.append(htoi(char1)! << 4 + htoi(char2)!)
    }

    return bytes
}

func htoi(_ value: UInt8) -> UInt8? {
    let char0 = UInt8(UnicodeScalar("0").value)
    let charA = UInt8(UnicodeScalar("a").value)

    switch value {
        case char0...char0 + 9:
            return value - char0
        case charA...charA + 5:
            return value - charA + 10
        default:
            return nil
    }
}
