/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import SwiftProtobuf
import XCTest

@testable import Biscuits

final class GenerationTests: XCTestCase {
    let rootPublicKey: Curve25519.Signing.PublicKey = try! Curve25519.Signing.PublicKey(
        rawRepresentation: hexDecode("1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284")!
    )

    let rootPrivateKey: Curve25519.Signing.PrivateKey = try! Curve25519.Signing.PrivateKey(
        rawRepresentation: hexDecode("99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61")!
    )

    func compareBiscuit(_ biscuit: Biscuit, with resource: String) throws {
        let biscuitPath = Bundle.module.path(forResource: resource, ofType: "bc")!
        let biscuitData = try! Data(contentsOf: URL(fileURLWithPath: biscuitPath), options: .mappedIfSafe)
        let expected = try Biscuit(serializedData: biscuitData) { _ in self.rootPublicKey }
        compareBlocks(expected.authority.datalog, biscuit.authority.datalog)
        XCTAssertEqual(expected.attenuations.count, biscuit.attenuations.count)
        for (expected, block) in zip(expected.attenuations, biscuit.attenuations) {
            XCTAssertEqual(expected.signedByThirdParty, block.signedByThirdParty)
            compareBlocks(expected.datalog, block.datalog)
        }
    }

    func compareBlocks(_ lhs: Biscuit.DatalogBlock, _ rhs: Biscuit.DatalogBlock) {
        XCTAssertEqual(lhs.symbols, rhs.symbols)
        XCTAssertEqual(lhs.publicKeys, rhs.publicKeys)
        XCTAssertEqual(lhs.trusted, rhs.trusted)
        XCTAssertEqual(lhs.context, rhs.context)
        XCTAssertEqual(lhs.facts, rhs.facts)
        compareRules(lhs.rules, rhs.rules)
        compareChecks(lhs.checks, rhs.checks)
    }

    func compareChecks(_ lhs: [Check], _ rhs: [Check]) {
        XCTAssertEqual(lhs.count, rhs.count)
        for (lhs, rhs) in zip(lhs, rhs) {
            compareQueries(lhs.queries, rhs.queries)
            XCTAssertEqual(lhs.kind, rhs.kind)
        }
    }

    func compareQueries(_ lhs: [Biscuit.Query], _ rhs: [Biscuit.Query]) {
        XCTAssertEqual(lhs.count, rhs.count)
        for (lhs, rhs) in zip(lhs, rhs) {
            XCTAssertEqual(lhs.predicates, rhs.predicates)
            XCTAssertEqual(lhs.expressions, rhs.expressions)
            XCTAssertEqual(lhs.trusted, rhs.trusted)
        }
    }

    func compareRules(_ lhs: [Rule], _ rhs: [Rule]) {
        XCTAssertEqual(lhs.count, rhs.count)
        for (lhs, rhs) in zip(lhs, rhs) {
            XCTAssertEqual(lhs.head, rhs.head)
            XCTAssertEqual(lhs.bodyPredicates, rhs.bodyPredicates)
            XCTAssertEqual(lhs.expressions, rhs.expressions)
            XCTAssertEqual(lhs.trusted, rhs.trusted)
        }
    }

    func testBasicToken() throws {
        var biscuit = try Biscuit(
            authorityBlock: """
                    right("file1", "read");
                    right("file2", "read");
                    right("file1", "write");
                """,
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    check if resource($0), operation("read"), right($0, "read");
                """
        )
        try compareBiscuit(biscuit, with: "test001_basic")
    }

    func testBasicTokenDSL() throws {
        var biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Fact("right", "file1", "read")
            Fact("right", "file2", "read")
            Fact("right", "file1", "write")
        }
        biscuit = try biscuit.attenuated {
            Check.checkIf {
                Predicate("resource", Term(variable: "0"))
                Predicate("operation", "read")
                Predicate("right", Term(variable: "0"), "read")
            }
        }
        try compareBiscuit(biscuit, with: "test001_basic")
    }

    func testScopedRules() throws {
        var biscuit = try Biscuit(
            authorityBlock: """
                    user_id("alice");
                    owner("alice", "file1");
                """,
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    right($0, "read") <- resource($0), user_id($1), owner($1, $0);
                    check if resource($0), operation("read"), right($0, "read");
                """
        )
        biscuit = try biscuit.attenuated(
            using: """
                    owner("alice", "file2");
                """
        )
        try compareBiscuit(biscuit, with: "test007_scoped_rules")
    }

    func testScopedRulesDSL() throws {
        var biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Fact("user_id", "alice")
            Fact("owner", "alice", "file1")
        }
        biscuit = try biscuit.attenuated {
            try Rule(head: Predicate("right", Term(variable: "0"), "read")) {
                Predicate("resource", Term(variable: "0"))
                Predicate("user_id", Term(variable: "1"))
                Predicate("owner", Term(variable: "1"), Term(variable: "0"))
            }
            Check.checkIf {
                Predicate("resource", Term(variable: "0"))
                Predicate("operation", "read")
                Predicate("right", Term(variable: "0"), "read")
            }
        }
        biscuit = try biscuit.attenuated {
            Fact("owner", "alice", "file2")
        }
        try compareBiscuit(biscuit, with: "test007_scoped_rules")
    }

    func testScopedChecks() throws {
        var biscuit = try Biscuit(
            authorityBlock: """
                right("file1", "read");
                """,
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                check if resource($0), operation("read"), right($0, "read");
                """
        )
        biscuit = try biscuit.attenuated(
            using: """
                right("file2", "read");
                """
        )
        try compareBiscuit(biscuit, with: "test008_scoped_checks")
    }

    func testScopedChecksDSL() throws {
        var biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Fact("right", "file1", "read")
        }
        biscuit = try biscuit.attenuated {
            Check.checkIf {
                Predicate("resource", Term(variable: "0"))
                Predicate("operation", "read")
                Predicate("right", Term(variable: "0"), "read")
            }
        }
        biscuit = try biscuit.attenuated {
            Fact("right", "file2", "read")
        }
        try compareBiscuit(biscuit, with: "test008_scoped_checks")
    }

    func testExpiredToken() throws {
        var biscuit = try Biscuit(
            authorityBlock: "",
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    check if resource("file1");
                    check if time($time), $time <= 2018-12-20T00:00:00Z;
                """
        )
        try compareBiscuit(biscuit, with: "test009_expired_token")
    }

    func testExpiredTokenDSL() throws {
        let date = ISO8601DateFormatter().date(from: "2018-12-20T00:00:00Z")!
        var biscuit = try Biscuit(rootKey: self.rootPrivateKey) {}
        biscuit = try biscuit.attenuated {
            Check.checkIf { Predicate("resource", "file1") }
            Check.checkIf {
                Predicate("time", Term(variable: "time"))
                Term(variable: "time").lessThanOrEqual(date)
            }
        }
        try compareBiscuit(biscuit, with: "test009_expired_token")
    }

    func testRegexConstraint() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if resource($0), $0.matches("file[0-9]+.txt");
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test014_regex_constraint")
    }

    func testRegexConstraintDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.checkIf {
                Predicate("resource", Term(variable: "0"))
                Term(variable: "0").matches("file[0-9]+.txt")
            }
        }
        try compareBiscuit(biscuit, with: "test014_regex_constraint")
    }

    func testExpressions() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if true;
                    check if !false;
                    check if true === true;
                    check if false === false;
                    check if 1 < 2;
                    check if 2 > 1;
                    check if 1 <= 2;
                    check if 1 <= 1;
                    check if 2 >= 1;
                    check if 2 >= 2;
                    check if 3 === 3;
                    check if 1 + 2 * 3 - 4 / 2 === 5;
                    check if "hello world".starts_with("hello"), "hello world".ends_with("world");
                    check if "aaabde".matches("a*c?.e");
                    check if "aaabde".contains("abd");
                    check if "aaabde" === "aaa" + "b" + "de";
                    check if "abcD12" === "abcD12";
                    check if "abcD12".length() === 6;
                    check if "é".length() === 2;
                    check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z;
                    check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z;
                    check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z;
                    check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
                    check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z;
                    check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
                    check if 2020-12-04T09:46:41Z === 2020-12-04T09:46:41Z;
                    check if hex:12ab === hex:12ab;
                    check if {1, 2}.contains(2);
                    check if {2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z}.contains(2020-12-04T09:46:41Z);
                    check if {false, true}.contains(true);
                    check if {"abc", "def"}.contains("abc");
                    check if {hex:12ab, hex:34de}.contains(hex:34de);
                    check if {1, 2}.contains({2});
                    check if {1, 2} === {1, 2};
                    check if {1, 2}.intersection({2, 3}) === {2};
                    check if {1, 2}.union({2, 3}) === {1, 2, 3};
                    check if {1, 2, 3}.intersection({1, 2}).contains(1);
                    check if {1, 2, 3}.intersection({1, 2}).length() === 2;
                    check if {,}.length() === 0;
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test017_expressions")
    }

    func testExpressionsDSL() throws {
        let date2019 = ISO8601DateFormatter().date(from: "2019-12-04T09:46:41Z")!
        let date2020 = ISO8601DateFormatter().date(from: "2020-12-04T09:46:41Z")!
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.checkIf { true }
            Check.checkIf { Term(value: false).negated }
            Check.checkIf { Term(value: true).strictEqual(true) }
            Check.checkIf { Term(value: false).strictEqual(false) }
            Check.checkIf { Term(value: 1).lessThan(2) }
            Check.checkIf { Term(value: 2).greaterThan(1) }
            Check.checkIf { Term(value: 1).lessThanOrEqual(2) }
            Check.checkIf { Term(value: 1).lessThanOrEqual(1) }
            Check.checkIf { Term(value: 2).greaterThanOrEqual(1) }
            Check.checkIf { Term(value: 2).greaterThanOrEqual(2) }
            Check.checkIf { Term(value: 3).strictEqual(3) }
            Check.checkIf {
                Term(value: 1).add(Term(value: 2).multiply(3))
                    .subtract(Term(value: 4).divide(2))
                    .strictEqual(5)
            }
            Check.checkIf {
                Term(value: "hello world").startsWith("hello")
                Term(value: "hello world").endsWith("world")
            }
            Check.checkIf { Term(value: "aaabde").matches("a*c?.e") }
            Check.checkIf { Term(value: "aaabde").contains("abd") }
            Check.checkIf {
                Term(value: "aaabde").strictEqual(Term(value: "aaa").add("b").add("de"))
            }
            Check.checkIf { Term(value: "abcD12").strictEqual("abcD12") }
            Check.checkIf { Term(value: "abcD12").length.strictEqual(6) }
            Check.checkIf { Term(value: "é").length.strictEqual(2) }
            Check.checkIf { Term(value: date2019).lessThan(date2020) }
            Check.checkIf { Term(value: date2020).greaterThan(date2019) }
            Check.checkIf { Term(value: date2019).lessThanOrEqual(date2020) }
            Check.checkIf { Term(value: date2020).greaterThanOrEqual(date2020) }
            Check.checkIf { Term(value: date2020).greaterThanOrEqual(date2019) }
            Check.checkIf { Term(value: date2020).greaterThanOrEqual(date2020) }
            Check.checkIf { Term(value: date2020).strictEqual(date2020) }
            try Check.checkIf {
                try Value.bytes(hexString: "12ab").strictEqual(Value.bytes(hexString: "12ab"))
            }
            try Check.checkIf { try Value.set(1, 2).contains(2) }
            try Check.checkIf { try Value.set(date2019, date2020).contains(date2020) }
            try Check.checkIf { try Value.set(false, true).contains(true) }
            try Check.checkIf { try Value.set("abc", "def").contains("abc") }
            try Check.checkIf {
                try Value.set(Value.bytes(hexString: "12ab"), Value.bytes(hexString: "34de"))
                    .contains(Value.bytes(hexString: "34de"))
            }
            try Check.checkIf { try Value.set(1, 2).contains(Value.set(2)) }
            try Check.checkIf { try Value.set(1, 2).strictEqual(Value.set(1, 2)) }
            try Check.checkIf {
                try Value.set(1, 2).intersection(Value.set(2, 3)).strictEqual(Value.set(2))
            }
            try Check.checkIf {
                try Value.set(1, 2).union(Value.set(2, 3)).strictEqual(Value.set(1, 2, 3))
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).intersection(Value.set(1, 2)).contains(1)
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).intersection(Value.set(1, 2)).length.strictEqual(2)
            }
            Check.checkIf { Value.emptySet.length.strictEqual(0) }
        }
        try compareBiscuit(biscuit, with: "test017_expressions")
    }

    func testParsing() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                ns::fact_123("hello é	😁");
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test021_parsing")
    }

    func testDefaultSymbols() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    read(0);
                    write(1);
                    resource(2);
                    operation(3);
                    right(4);
                    time(5);
                    role(6);
                    owner(7);
                    tenant(8);
                    namespace(9);
                    user(10);
                    team(11);
                    service(12);
                    admin(13);
                    email(14);
                    group(15);
                    member(16);
                    ip_address(17);
                    client(18);
                    client_ip(19);
                    domain(20);
                    path(21);
                    version(22);
                    cluster(23);
                    node(24);
                    hostname(25);
                    nonce(26);
                    query(27);
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test022_default_symbols")
    }

    func testThirdParty() throws {
        var biscuit = try Biscuit(
            authorityBlock: """
                    right("read");
                    check if group("admin") trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
                """,
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    group("admin");
                    check if right("read");
                """,
            thirdPartyKey: Curve25519.Signing.PrivateKey()
        )
        try compareBiscuit(biscuit, with: "test024_third_party")
    }

    func testCheckAll() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    allowed_operations({"A", "B"});
                    check all operation($op), allowed_operations($allowed), $allowed.contains($op);
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test025_check_all")
    }

    func testCheckAllDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            try Fact("allowed_operations", Value.set("A", "B"))
            Check.checkAll {
                Predicate("operation", Term(variable: "op"))
                Predicate("allowed_operations", Term(variable: "allowed"))
                Term(variable: "allowed").contains(Term(variable: "op"))
            }
        }
        try compareBiscuit(biscuit, with: "test025_check_all")
    }

    func testPublicKeysInterning() throws {
        var biscuit = try Biscuit(
            authorityBlock: """
                    query(0);
                    check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
                """,
            rootKey: self.rootPrivateKey
        )
        biscuit = try biscuit.attenuated(
            using: """
                    query(1);
                    query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
                    check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
                    check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
                """,
            thirdPartyKey: Curve25519.Signing.PrivateKey()
        )
        biscuit = try biscuit.attenuated(
            using: """
                    query(2);
                    check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
                    check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
                """,
            thirdPartyKey: Curve25519.Signing.PrivateKey()
        )
        biscuit = try biscuit.attenuated(
            using: """
                    query(3);
                    check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
                    check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
                """,
            thirdPartyKey: Curve25519.Signing.PrivateKey()
        )
        biscuit = try biscuit.attenuated(
            using: """
                    query(4);
                    check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
                    check if query(4) trusting ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136;
                """
        )
        try compareBiscuit(biscuit, with: "test026_public_keys_interning")
    }

    func testPublicKeysInterningDSL() throws {
        let key1 = try Curve25519.Signing.PublicKey(
            rawRepresentation: hexDecode("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189")!
        )
        let key2 = try Curve25519.Signing.PublicKey(
            rawRepresentation: hexDecode("a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463")!
        )
        let key3 = try Curve25519.Signing.PublicKey(
            rawRepresentation: hexDecode("f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136")!
        )
        let query: (Int) -> Biscuits.Predicate = { x in Predicate("query", x) }
        let queryFact: (Int) -> Fact = { x in Fact("query", x) }

        var biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            queryFact(0)
            Check.checkIf(trusting: .previous, key1) { true }
        }
        biscuit = try biscuit.attenuated(thirdPartyKey: Curve25519.Signing.PrivateKey()) {
            queryFact(1)
            try Rule(head: Predicate("query", 1, 2), trusting: key2) {
                query(1)
                query(2)
            }
            Check.checkIf(trusting: key2) {
                query(2)
                query(3)
            }
            Check.checkIf(trusting: key1) {
                query(1)
            }
        }
        biscuit = try biscuit.attenuated(thirdPartyKey: Curve25519.Signing.PrivateKey()) {
            queryFact(2)
            Check.checkIf(trusting: key2) {
                query(2)
                query(3)
            }
            Check.checkIf(trusting: key1) {
                query(1)
            }
        }
        biscuit = try biscuit.attenuated(thirdPartyKey: Curve25519.Signing.PrivateKey()) {
            queryFact(3)
            Check.checkIf(trusting: key2) {
                query(2)
                query(3)
            }
            Check.checkIf(trusting: key1) {
                query(1)
            }
        }
        biscuit = try biscuit.attenuated {
            queryFact(4)
            Check.checkIf(trusting: key2) {
                query(2)
            }
            Check.checkIf(trusting: key3) {
                query(4)
            }
        }
        try compareBiscuit(biscuit, with: "test026_public_keys_interning")
    }

    func testIntegerWraparound() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if 10000000000 * 10000000000 !== 0;
                    check if 9223372036854775807 + 1 !== 0;
                    check if -9223372036854775808 - 1 !== 0;
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test027_integer_wraparound")
    }

    func testExpressionsV4() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if 1 !== 3;
                    check if 1 | 2 ^ 3 === 0;
                    check if "abcD12x" !== "abcD12";
                    check if 2022-12-04T09:46:41Z !== 2020-12-04T09:46:41Z;
                    check if hex:12abcd !== hex:12ab;
                    check if {1, 4} !== {1, 2};
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test028_expressions_v4")
    }

    func testRejectIf() throws {
        let biscuit = try Biscuit(
            authorityBlock: "reject if test($test), $test;",
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test029_reject_if")
    }

    func testRejectIfDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.rejectIf {
                Predicate("test", Term(variable: "test"))
                Term(variable: "test")
            }
        }
        try compareBiscuit(biscuit, with: "test029_reject_if")
    }

    func testNull() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if fact(null, $value), $value == null;
                    reject if fact(null, $value), $value != null;
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test030_null")
    }

    func testNullDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.checkIf {
                Predicate("fact", Value.null, Term(variable: "value"))
                Term(variable: "value").equal(Value.null)
            }
            Check.rejectIf {
                Predicate("fact", Value.null, Term(variable: "value"))
                Term(variable: "value").notEqual(Value.null)
            }
        }
        try compareBiscuit(biscuit, with: "test030_null")
    }

    func testLazinessClosures() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if !false && true;
                    check if false || true;
                    check if (true || false) && true;
                    check if !(false && "x".intersection("x"));
                    check if true || "x".intersection("x");
                    check if {1, 2, 3}.all($p -> $p > 0);
                    check if !{1, 2, 3}.all($p -> $p == 2);
                    check if {1, 2, 3}.any($p -> $p > 2);
                    check if !{1, 2, 3}.any($p -> $p > 3);
                    check if {1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q));
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test032_laziness_closures")
    }

    func testLazinessClosuresDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.checkIf { Term(value: false).negated.and(true) }
            Check.checkIf { Term(value: false).or(true) }
            Check.checkIf { Term(value: true).or(false).parenthesized.and(true) }
            Check.checkIf { Term(value: false).and(Term(value: "x").intersection("x")).parenthesized.negated }
            Check.checkIf { Term(value: true).or(Term(value: "x").intersection("x")) }
            try Check.checkIf {
                try Value.set(1, 2, 3).all(Closure("p", body: Term(variable: "p").greaterThan(0)))
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).all(Closure("p", body: Term(variable: "p").equal(2))).negated
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).any(Closure("p", body: Term(variable: "p").greaterThan(2)))
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).any(Closure("p", body: Term(variable: "p").greaterThan(3))).negated
            }
            try Check.checkIf {
                try Value.set(1, 2, 3).any(
                    Closure(
                        "p",
                        body: Term(variable: "p").greaterThan(1).and(
                            try Value.set(3, 4, 5).any(
                                Closure(
                                    "q",
                                    body: Term(variable: "p").equal(Term(variable: "q"))
                                )
                            )
                        )
                    )
                )
            }
        }
        try compareBiscuit(biscuit, with: "test032_laziness_closures")
    }

    func testTypeOf() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    integer(1);
                    string("test");
                    date(2023-12-28T00:00:00Z);
                    bytes(hex:aa);
                    bool(true);
                    set({false, true});
                    null(null);
                    array([1, 2, 3]);
                    map({"a": true});
                    check if 1.type() == "integer";
                    check if integer($t), $t.type() == "integer";
                    check if "test".type() == "string";
                    check if string($t), $t.type() == "string";
                    check if (2023-12-28T00:00:00Z).type() == "date";
                    check if date($t), $t.type() == "date";
                    check if hex:aa.type() == "bytes";
                    check if bytes($t), $t.type() == "bytes";
                    check if true.type() == "bool";
                    check if bool($t), $t.type() == "bool";
                    check if {false, true}.type() == "set";
                    check if set($t), $t.type() == "set";
                    check if null.type() == "null";
                    check if null($t), $t.type() == "null";
                    check if array($t), $t.type() == "array";
                    check if map($t), $t.type() == "map";
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test033_typeof")
    }

    func testArrayMap() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if [1, 2, 1].length() == 3;
                    check if ["a", "b"] != true;
                    check if ["a", "b"] != [1, 2, 3];
                    check if ["a", "b"] == ["a", "b"];
                    check if ["a", "b"] === ["a", "b"];
                    check if ["a", "b"] !== ["a", "c"];
                    check if ["a", "b", "c"].contains("c");
                    check if [1, 2, 3].starts_with([1, 2]);
                    check if [4, 5, 6].ends_with([6]);
                    check if [1, 2, "a"].get(2) == "a";
                    check if [1, 2].get(3) == null;
                    check if [1, 2, 3].all($p -> $p > 0);
                    check if [1, 2, 3].any($p -> $p > 2);
                    check if {"a": 1, "b": 2, "c": 3, "d": 4}.length() == 4;
                    check if {1: "a", 2: "b"} != true;
                    check if {1: "a", 2: "b"} != {"a": 1, "b": 2};
                    check if {1: "a", 2: "b"} == {1: "a", 2: "b"};
                    check if {1: "a", 2: "b"} !== {"a": 1, "b": 2};
                    check if {1: "a", 2: "b"} === {1: "a", 2: "b"};
                    check if {"a": 1, "b": 2, "c": 3, "d": 4}.contains("d");
                    check if {1: "A", "a": 1, "b": 2}.get("a") == 1;
                    check if {1: "A", "a": 1, "b": 2}.get(1) == "A";
                    check if {1: "A", "a": 1, "b": 2}.get("c") == null;
                    check if {1: "A", "a": 1, "b": 2}.get(2) == null;
                    check if {"a": 1, "b": 2}.all($kv -> $kv.get(0) != "c" && $kv.get(1) < 3);
                    check if {1: "A", "a": 1, "b": 2}.any($kv -> $kv.get(0) == 1 && $kv.get(1) == "A");
                    check if {"user": {"id": 1, "roles": ["admin"]}}.get("user").get("roles").contains("admin");
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test034_array_map")
    }

    func testTryOr() throws {
        let biscuit = try Biscuit(
            authorityBlock: """
                    check if (true === 12).try_or(true);
                    check if ((true === 12).try_or(true === 12)).try_or(true);
                    reject if (true == 12).try_or(true);
                """,
            rootKey: self.rootPrivateKey
        )
        try compareBiscuit(biscuit, with: "test038_try_op")
    }

    func testTryOrDSL() throws {
        let biscuit = try Biscuit(rootKey: self.rootPrivateKey) {
            Check.checkIf {
                Term(value: true).strictEqual(12).parenthesized.tryOr(true)
            }
            Check.checkIf {
                Term(value: true).strictEqual(12).parenthesized.tryOr(Term(value: true).strictEqual(12)).parenthesized
                    .tryOr(true)
            }
            Check.rejectIf {
                Term(value: true).equal(12).parenthesized.tryOr(true)
            }
        }
        try compareBiscuit(biscuit, with: "test038_try_op")
    }
}
