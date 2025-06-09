/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import XCTest
@testable import Biscuits

final class DatalogPrintingTests: XCTestCase {
    func testPrintExpression() {
        XCTAssertEqual("\(0.term.lessThan(1))", "0 < 1")
        XCTAssertEqual("\(true.term.equal(false.term.negated))", "true == !false")
        XCTAssertEqual("\(Value.emptySet.contains(100))", "{}.contains(100)")
        XCTAssertEqual("\(Term(variable: "x").add(1))", "$x + 1")
        XCTAssertEqual("\(Data([0, 0]).term.length)", "hex:0000.length()")
    }

    func testPrintFact() {
        XCTAssertEqual("\(Fact("user", 1234))", "user(1234)")
    }

    func testPrintRule() throws {
        XCTAssertEqual(
            try Rule(head: Predicate("mortal", Term(variable: "Socrates"))) {
                Predicate("human", Term(variable: "Socrates"))
            }.description,
            "mortal($Socrates) <- human($Socrates)"
        )
        XCTAssertEqual(
            "\(try Rule(head: Predicate("x", 0), trusting: .previous) { Predicate("y", 1); true })",
            "x(0) <- y(1), true trusting previous"
        )
    }

    func testPrintCheck() {
        XCTAssertEqual(
            "\(Check.checkIf(trusting: .authority) { Predicate("user", 1234) })",
            "check if user(1234) trusting authority"
        )
        XCTAssertEqual(
            Check.checkAll {
                Predicate("operation", Term(variable: "op"))
                Term(variable: "op").notEqual("write")
            }.description,
            "check all operation($op), $op != \"write\""
        )
        XCTAssertEqual(
            Check.rejectIf {
                Predicate("operation", Term(variable: "op"))
                Term(variable: "op").equal("write")
            }.description,
            "reject if operation($op), $op == \"write\""
        )
    }

    func testPrintAllow() {
        XCTAssertEqual(
            "\(Policy.allowIf { true })",
            "allow if true"
        )
        XCTAssertEqual(
            "\(Policy.allowIf(trusting: .authority, .previous) { Predicate("user", 1234) })",
            "allow if user(1234) trusting authority, previous"
        )
    }

    func testPrintDeny() {
        XCTAssertEqual(
            "\(Policy.denyIf { Predicate("user", 1234) })",
            "deny if user(1234)"
        )
        XCTAssertEqual(
            "\(Policy.denyIf(trusting: .previous) { Predicate("x", false) })",
            "deny if x(false) trusting previous"
        )
    }
}
