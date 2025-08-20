/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import XCTest

@testable import Biscuits

final class BiscuitsTests: XCTestCase {
    func testDatalogBlockWithFact() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("foo(1234);")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.checks.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.trusted.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)

        XCTAssertEqual(block.symbols, ["foo"])
        XCTAssertEqual(block.facts.count, 1)
        let fact = block.facts[0]
        XCTAssertEqual(fact.name, "foo")
        XCTAssertEqual(fact.values, [1234.value])
    }

    func testDatalogBlockWithRule() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("foo($bar) <- user($bar);")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.checks.isEmpty)
        XCTAssert(block.trusted.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)

        XCTAssertEqual(block.symbols, ["foo", "bar"])
        XCTAssertEqual(block.rules.count, 1)
        let rule = block.rules[0]
        XCTAssert(rule.expressions.isEmpty)
        XCTAssert(rule.trusted.isEmpty)
        let head = rule.head
        XCTAssertEqual(head.name, "foo")
        XCTAssertEqual(head.terms, [Term(variable: "bar")])
        XCTAssertEqual(rule.bodyPredicates.count, 1)
        let body = rule.bodyPredicates[0]
        XCTAssertEqual(body.name, "user")
        XCTAssertEqual(body.terms, [Term(variable: "bar")])
    }

    func testDatalogBlockWithCheck() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("check if foo(\"bar\", \"foo\");")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.trusted.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)

        XCTAssertEqual(block.symbols, ["foo", "bar"])
        XCTAssertEqual(block.checks.count, 1)
        let check = block.checks[0]
        XCTAssertEqual(check.kind, .checkIf)
        XCTAssertEqual(check.queries.count, 1)
        let query = check.queries[0]
        XCTAssert(query.expressions.isEmpty)
        XCTAssert(query.trusted.isEmpty)
        XCTAssertEqual(query.predicates.count, 1)
        let body = query.predicates[0]
        XCTAssertEqual(body.name, "foo")
        XCTAssertEqual(body.terms, ["bar".term, "foo".term])
    }

    func testDatalogBlockWithMultipleFacts() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("user(1234); admin(1234);")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.checks.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.trusted.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)
        XCTAssert(block.symbols.isEmpty)

        XCTAssertEqual(block.facts.count, 2)
        let fact1 = block.facts[0]
        XCTAssertEqual(fact1.name, "user")
        XCTAssertEqual(fact1.values, [1234.value])
        let fact2 = block.facts[1]
        XCTAssertEqual(fact2.name, "admin")
        XCTAssertEqual(fact2.values, [1234.value])
    }

    func testDatalogBlockWithExpression() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("user($x) <- member($x, $team), $team == \"foo\";")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.checks.isEmpty)
        XCTAssert(block.trusted.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)

        XCTAssertEqual(block.symbols, ["x", "foo"])
        XCTAssertEqual(block.rules.count, 1)
        let rule = block.rules[0]
        XCTAssert(rule.trusted.isEmpty)
        let head = rule.head
        XCTAssertEqual(head.name, "user")
        XCTAssertEqual(head.terms, [Term(variable: "x")])
        XCTAssertEqual(rule.bodyPredicates.count, 1)
        let body = rule.bodyPredicates[0]
        XCTAssertEqual(body.name, "member")
        XCTAssertEqual(body.terms, [Term(variable: "x"), Term(variable: "team")])
        XCTAssertEqual(rule.expressions.count, 1)
        let expr = rule.expressions[0]
        XCTAssertEqual(expr.ops.count, 3)
        XCTAssertEqual(expr.ops[0], .value(Term(variable: "team")))
        XCTAssertEqual(expr.ops[1], .value("foo".term))
        XCTAssertEqual(expr.ops[2], .binary(.heterogeneousEqual))
    }

    func testDatalogBlockWithScope() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("trusting previous; check if user(1234);")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)
        XCTAssert(block.symbols.isEmpty)

        XCTAssertEqual(block.trusted, [.previous])
        XCTAssertEqual(block.checks.count, 1)
        let check = block.checks[0]
        XCTAssertEqual(check.kind, .checkIf)
        XCTAssertEqual(check.queries.count, 1)
        let query = check.queries[0]
        XCTAssert(query.expressions.isEmpty)
        XCTAssert(query.trusted.isEmpty)
        XCTAssertEqual(query.predicates.count, 1)
        let body = query.predicates[0]
        XCTAssertEqual(body.name, "user")
        XCTAssertEqual(body.terms, [1234.term])
    }

    func testDatalogBlockWithRuleWithScope() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock("check if user(1234) trusting authority;")
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.publicKeys.isEmpty)
        XCTAssert(block.symbols.isEmpty)
        XCTAssert(block.trusted.isEmpty)

        XCTAssertEqual(block.checks.count, 1)
        let check = block.checks[0]
        XCTAssertEqual(check.kind, .checkIf)
        XCTAssertEqual(check.queries.count, 1)
        let query = check.queries[0]
        XCTAssert(query.expressions.isEmpty)
        XCTAssertEqual(query.trusted, [.authority])
        XCTAssertEqual(query.predicates.count, 1)
        let body = query.predicates[0]
        XCTAssertEqual(body.name, "user")
        XCTAssertEqual(body.terms, [1234.term])
    }

    func testDatalogBlockWithEd25519Scope() throws {
        var interner = BlockInternmentTable()
        var block = try Biscuit.DatalogBlock(
            """
                trusting ed25519/0605d9692dd565fa8d70419081e032638fbc6dff5d96d14aeab49bc36a46d6a2;
                check if user(1234);
            """
        )
        block.attachToBiscuit(interner: &interner, context: nil)
        XCTAssertEqual(block.version, 6)
        XCTAssertEqual(block.context, nil)
        XCTAssert(block.facts.isEmpty)
        XCTAssert(block.rules.isEmpty)
        XCTAssert(block.symbols.isEmpty)

        XCTAssertEqual(block.trusted.count, 1)
        XCTAssertEqual(block.publicKeys.count, 1)
        XCTAssertEqual(block.checks.count, 1)
        let check = block.checks[0]
        XCTAssertEqual(check.kind, .checkIf)
        XCTAssertEqual(check.queries.count, 1)
        let query = check.queries[0]
        XCTAssert(query.expressions.isEmpty)
        XCTAssertEqual(query.predicates.count, 1)
        let body = query.predicates[0]
        XCTAssertEqual(body.name, "user")
        XCTAssertEqual(body.terms, [1234.term])
    }

    func testBiscuitConstructionFromString() throws {
        var interner = BlockInternmentTable()
        let key = P256.Signing.PrivateKey()
        var block = try Biscuit.DatalogBlock("user(1234);")
        block.attachToBiscuit(interner: &interner, context: nil)
        let biscuit = try Biscuit(authorityBlock: "user(1234);", rootKey: key)
        XCTAssertEqual(biscuit.rootKeyID, nil)
        XCTAssert(biscuit.attenuations.isEmpty)

        let authority = biscuit.authority
        XCTAssertEqual(authority.nextKey.algorithm, .ed25519)
        XCTAssertEqual(authority.datalog.version, block.version)
        XCTAssertEqual(authority.datalog.symbols, block.symbols)
        XCTAssertEqual(authority.datalog.context, block.context)
        XCTAssertEqual(authority.datalog.checks, block.checks)
        XCTAssertEqual(authority.datalog.facts, block.facts)
        XCTAssertEqual(authority.datalog.rules, block.rules)
        XCTAssertEqual(authority.datalog.trusted, block.trusted)
        XCTAssert(authority.datalog.publicKeys.isEmpty)
    }

    func testBiscuitConstructionFromDSL() throws {
        var interner = BlockInternmentTable()
        let key = P256.Signing.PrivateKey()
        var block = try Biscuit.DatalogBlock("user(1234);")
        block.attachToBiscuit(interner: &interner, context: nil)
        let biscuit = try Biscuit(rootKey: key) {
            Fact("user", 1234)
        }
        XCTAssertEqual(biscuit.rootKeyID, nil)
        XCTAssert(biscuit.attenuations.isEmpty)

        let authority = biscuit.authority
        XCTAssertEqual(authority.nextKey.algorithm, .ed25519)
        XCTAssertEqual(authority.datalog.version, block.version)
        XCTAssertEqual(authority.datalog.symbols, block.symbols)
        XCTAssertEqual(authority.datalog.context, block.context)
        XCTAssertEqual(authority.datalog.checks, block.checks)
        XCTAssertEqual(authority.datalog.facts, block.facts)
        XCTAssertEqual(authority.datalog.rules, block.rules)
        XCTAssertEqual(authority.datalog.trusted, block.trusted)
        XCTAssert(authority.datalog.publicKeys.isEmpty)
    }

    func testBiscuitAttenuationFromString() throws {
        var interner = BlockInternmentTable()
        let key = P256.Signing.PrivateKey()
        let biscuit = try Biscuit(authorityBlock: "user(1234);", rootKey: key)
        var attenuation = try Biscuit.DatalogBlock("check if read(\"/foo\");")
        attenuation.attachToBiscuit(interner: &interner, context: nil)
        let attenuated = try biscuit.attenuated(using: "check if read(\"/foo\");", algorithm: .secp256r1)
        XCTAssertEqual(attenuated.attenuations.count, 1)

        let attenuation_block = attenuated.attenuations[0]
        XCTAssertEqual(attenuation_block.nextKey.algorithm, .secp256r1)
        XCTAssertEqual(attenuation_block.datalog.version, attenuation.version)
        XCTAssertEqual(attenuation_block.datalog.symbols, attenuation.symbols)
        XCTAssertEqual(attenuation_block.datalog.context, attenuation.context)
        XCTAssertEqual(attenuation_block.datalog.checks, attenuation.checks)
        XCTAssertEqual(attenuation_block.datalog.facts, attenuation.facts)
        XCTAssertEqual(attenuation_block.datalog.rules, attenuation.rules)
        XCTAssertEqual(attenuation_block.datalog.trusted, attenuation.trusted)
        XCTAssert(attenuation_block.datalog.publicKeys.isEmpty)
    }

    func testBiscuitAttenuationFromDSL() throws {
        var interner = BlockInternmentTable()
        let key = P256.Signing.PrivateKey()
        let biscuit = try Biscuit(rootKey: key) {
            Fact("user", 1234)
        }
        var attenuation = try Biscuit.DatalogBlock("check if read(\"/foo\");")
        attenuation.attachToBiscuit(interner: &interner, context: nil)
        let attenuated = try biscuit.attenuated(algorithm: .secp256r1) {
            Check.checkIf { Predicate("read", "/foo") }
        }
        XCTAssertEqual(attenuated.attenuations.count, 1)

        let attenuation_block = attenuated.attenuations[0]
        XCTAssertEqual(attenuation_block.nextKey.algorithm, .secp256r1)
        XCTAssertEqual(attenuation_block.datalog.version, attenuation.version)
        XCTAssertEqual(attenuation_block.datalog.symbols, attenuation.symbols)
        XCTAssertEqual(attenuation_block.datalog.context, attenuation.context)
        XCTAssertEqual(attenuation_block.datalog.checks, attenuation.checks)
        XCTAssertEqual(attenuation_block.datalog.facts, attenuation.facts)
        XCTAssertEqual(attenuation_block.datalog.rules, attenuation.rules)
        XCTAssertEqual(attenuation_block.datalog.trusted, attenuation.trusted)
        XCTAssert(attenuation_block.datalog.publicKeys.isEmpty)
    }

    func testThirdPartySymbolTables() throws {
        let rootKey = Curve25519.Signing.PrivateKey()
        let thirdPartyKey = Curve25519.Signing.PrivateKey()
        var biscuit = try Biscuit(
            authorityBlock: """
                    foo("bar");
                    bar("foo");
                """,
            rootKey: rootKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    baz($0) <- bar($0), "foo" == $0;
                    check if foo("bar");
                """,
            thirdPartyKey: thirdPartyKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    check if baz("foo") trusting previous;
                """
        )
        try biscuit.authorize(using: "allow if true;")
    }

    func testVariablesOfDifferentTypes() throws {
        let rootKey = Curve25519.Signing.PrivateKey()
        let biscuit = try Biscuit(
            authorityBlock: """
                    resource(0);
                    resource("foo");
                    check if resource($x), $x == "foo";
                    check if resource($x), $x == 0;
                    check all resource($x), $x == 0 || $x == "foo";
                """,
            rootKey: rootKey
        )
        try biscuit.authorize(using: "allow if true;")
    }

    func testPrecedence() throws {
        let biscuit = try Biscuit(
            authorityBlock: "check if 1 + 2 * 3 - 4 / 2 == 5;",
            rootKey: Curve25519.Signing.PrivateKey()
        )
        try biscuit.authorize(using: "allow if true;")
        do {
            let _ = try biscuit.authorize(using: "allow if 1 < 2 < 3;")
        } catch let error as Biscuit.DatalogError where error == Biscuit.DatalogError.chainedComparisonsWithoutParens {
            return
        }
        XCTAssert(false)
    }

    func testThirdPartyBlockAPI() throws {
        let rootKey = Curve25519.Signing.PrivateKey()
        let thirdPartyKey = Curve25519.Signing.PrivateKey()
        let biscuit = try Biscuit(authorityBlock: "user(1);", rootKey: rootKey)
        let request = biscuit.generateThirdPartyBlockRequest()
        let contents = try request.generateBlock(
            using: "check if user(1), group(2);",
            privateKey: thirdPartyKey
        )
        let attenuatedBiscuit = try biscuit.attenuated(using: contents)
        do {
            try attenuatedBiscuit.authorize(using: "allow if true;")
            XCTAssert(false)
        } catch {}
        try attenuatedBiscuit.authorize(using: "group(2); allow if true;")
    }

    func testBase64URLEncoding() throws {
        // Generated with biscuit-cli by running:
        //   $ biscuit keypair --only-private-key --key-algorithm ed25519
        // Then manually trimming the algorithm prefix.
        let rootPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: hexDecode("ffedda2d87d1735763a707838833f3539b4a0d6cd53c6ded31875162ca0b8e83")!
        )
        // Generated with biscuit-cli, by running this (with private key from above `biscuit keypair` command):
        //   $ echo 'flavor("buttermilk")' | biscuit generate --private-key "ed25519/ffedda2d87d1735763a707838833f3539b4a0d6cd53c6ded31875162ca0b8e83" -
        let encodedBiscuit =
            "EowBCiIKBmZsYXZvcgoKYnV0dGVybWlsaxgDIgoKCAiACBIDGIEIEiQIABIgl0EWCFozow3RiEOtTcpY0O7ZADutOWZZ3wTJ0QKx5XMaQI4VPeolN94zLHxvP0JDvSuBeMe3wGmkcsD32u2wGegMdQiK78hiNclVjUr_9MOlHEr72kPIPiTQNXmk6AvlEggiIgogRWH7vgsJR3d8xreGt_8Trodp4x9eRZSgbBvDQzUeh9s="

        // Make sure we can construct the biscuit, and verify it was signed with our private key.
        let biscuit = try Biscuit(
            base64URLEncoded: encodedBiscuit,
            rootKey: rootPrivateKey.publicKey
        )

        // Now re-encode the biscuit and make sure we arrive at the same thing we started with.
        XCTAssertEqual(try biscuit.base64URLEncoded(), encodedBiscuit)
    }

    func testEmptyCheckAll() throws {
        let rootPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: hexDecode("ffedda2d87d1735763a707838833f3539b4a0d6cd53c6ded31875162ca0b8e83")!
        )
        let biscuit = try Biscuit(rootKey: rootPrivateKey) {
            Check.checkAll { Predicate("foo", true) }
        }
        do {
            try biscuit.authorize { Policy.alwaysAllow }
            XCTAssert(false)
        } catch {}
    }
}
