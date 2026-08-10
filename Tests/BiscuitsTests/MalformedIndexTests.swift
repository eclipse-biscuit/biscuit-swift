/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import Crypto
import SwiftProtobuf
import XCTest

@testable import Biscuits

final class MalformedIndexTests: XCTestCase {
    let rootPublicKey: Curve25519.Signing.PublicKey = try! Curve25519.Signing.PublicKey(
        rawRepresentation: hexDecode("1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284")!
    )

    func token(withAuthorityDatalog datalog: Biscuit_Format_Schema_Block) throws -> Data {
        let path = Bundle.module.path(forResource: "test001_basic", ofType: "bc")!
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        var proto = try Biscuit_Format_Schema_Biscuit(serializedBytes: data)
        proto.authority.block = try datalog.serializedData()
        return try proto.serializedData()
    }

    func assertRejects(_ datalog: Biscuit_Format_Schema_Block) throws {
        let data = try self.token(withAuthorityDatalog: datalog)
        XCTAssertThrowsError(try Biscuit(serializedData: data, rootKey: self.rootPublicKey)) { error in
            XCTAssertEqual(error as? Biscuit.ValidationError, Biscuit.ValidationError.invalidIndex)
        }
        XCTAssertThrowsError(try UnverifiedBiscuit(serializedData: data)) { error in
            XCTAssertEqual(error as? Biscuit.ValidationError, Biscuit.ValidationError.invalidIndex)
        }
    }

    func blockWithFactTerm(_ term: Biscuit_Format_Schema_Term) -> Biscuit_Format_Schema_Block {
        var predicate = Biscuit_Format_Schema_Predicate()
        predicate.name = 0
        predicate.terms = [term]
        var fact = Biscuit_Format_Schema_Fact()
        fact.predicate = predicate
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.facts = [fact]
        return block
    }

    func blockWithOp(_ op: Biscuit_Format_Schema_Op) -> Biscuit_Format_Schema_Block {
        var head = Biscuit_Format_Schema_Predicate()
        head.name = 0
        var expression = Biscuit_Format_Schema_Expression()
        expression.ops = [op]
        var rule = Biscuit_Format_Schema_Rule()
        rule.head = head
        rule.expressions = [expression]
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.rules = [rule]
        return block
    }

    func blockWithScope(publicKey: Int64) -> Biscuit_Format_Schema_Block {
        var scope = Biscuit_Format_Schema_Scope()
        scope.publicKey = publicKey
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.scope = [scope]
        return block
    }

    func testPredicateNameNotRepresentableAsInt() throws {
        var predicate = Biscuit_Format_Schema_Predicate()
        predicate.name = UInt64.max
        var fact = Biscuit_Format_Schema_Fact()
        fact.predicate = predicate
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.facts = [fact]
        try self.assertRejects(block)
    }

    func testPredicateNamePastEndOfSymbolTable() throws {
        var predicate = Biscuit_Format_Schema_Predicate()
        predicate.name = 1024
        var fact = Biscuit_Format_Schema_Fact()
        fact.predicate = predicate
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.facts = [fact]
        try self.assertRejects(block)
    }

    func testPredicateNamePastEndOfDefaultSymbolTable() throws {
        var predicate = Biscuit_Format_Schema_Predicate()
        predicate.name = 1023
        var fact = Biscuit_Format_Schema_Fact()
        fact.predicate = predicate
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.facts = [fact]
        try self.assertRejects(block)
    }

    func testStringTermNotRepresentableAsInt() throws {
        var term = Biscuit_Format_Schema_Term()
        term.string = UInt64.max
        try self.assertRejects(self.blockWithFactTerm(term))
    }

    func testVariableTermPastEndOfSymbolTable() throws {
        var term = Biscuit_Format_Schema_Term()
        term.variable = UInt32.max
        var predicate = Biscuit_Format_Schema_Predicate()
        predicate.name = 0
        predicate.terms = [term]
        var head = Biscuit_Format_Schema_Predicate()
        head.name = 0
        var rule = Biscuit_Format_Schema_Rule()
        rule.head = head
        rule.body = [predicate]
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.rules = [rule]
        try self.assertRejects(block)
    }

    func testSetElementNotRepresentableAsInt() throws {
        var element = Biscuit_Format_Schema_Term()
        element.string = UInt64.max
        var set = Biscuit_Format_Schema_TermSet()
        set.set = [element]
        var term = Biscuit_Format_Schema_Term()
        term.set = set
        try self.assertRejects(self.blockWithFactTerm(term))
    }

    func testArrayElementNotRepresentableAsInt() throws {
        var element = Biscuit_Format_Schema_Term()
        element.string = UInt64.max
        var array = Biscuit_Format_Schema_Array()
        array.array = [element]
        var term = Biscuit_Format_Schema_Term()
        term.array = array
        try self.assertRejects(self.blockWithFactTerm(term))
    }

    func testMapKeyNotRepresentableAsInt() throws {
        var key = Biscuit_Format_Schema_MapKey()
        key.string = UInt64.max
        var value = Biscuit_Format_Schema_Term()
        value.integer = 0
        var entry = Biscuit_Format_Schema_MapEntry()
        entry.key = key
        entry.value = value
        var map = Biscuit_Format_Schema_Map()
        map.entries = [entry]
        var term = Biscuit_Format_Schema_Term()
        term.map = map
        try self.assertRejects(self.blockWithFactTerm(term))
    }

    func testUnaryFfiNameNotRepresentableAsInt() throws {
        var unary = Biscuit_Format_Schema_OpUnary()
        unary.kind = .ffi
        unary.ffiName = UInt64.max
        var op = Biscuit_Format_Schema_Op()
        op.unary = unary
        try self.assertRejects(self.blockWithOp(op))
    }

    func testBinaryFfiNameNotRepresentableAsInt() throws {
        var binary = Biscuit_Format_Schema_OpBinary()
        binary.kind = .ffi
        binary.ffiName = UInt64.max
        var op = Biscuit_Format_Schema_Op()
        op.binary = binary
        try self.assertRejects(self.blockWithOp(op))
    }

    func testClosureParameterPastEndOfSymbolTable() throws {
        var closure = Biscuit_Format_Schema_OpClosure()
        closure.params = [UInt32.max]
        var op = Biscuit_Format_Schema_Op()
        op.closure = closure
        try self.assertRejects(self.blockWithOp(op))
    }

    func testNegativeScopePublicKey() throws {
        try self.assertRejects(self.blockWithScope(publicKey: -1))
    }

    func testMostNegativeScopePublicKey() throws {
        try self.assertRejects(self.blockWithScope(publicKey: Int64.min))
    }

    func testScopePublicKeyPastEndOfPublicKeyTable() throws {
        try self.assertRejects(self.blockWithScope(publicKey: Int64.max))
    }

    func testNegativeScopePublicKeyInRule() throws {
        var scope = Biscuit_Format_Schema_Scope()
        scope.publicKey = -1
        var head = Biscuit_Format_Schema_Predicate()
        head.name = 0
        var rule = Biscuit_Format_Schema_Rule()
        rule.head = head
        rule.scope = [scope]
        var block = Biscuit_Format_Schema_Block()
        block.version = 6
        block.rules = [rule]
        try self.assertRejects(block)
    }

    func testLargeRootKeyID() throws {
        let path = Bundle.module.path(forResource: "test001_basic", ofType: "bc")!
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        var proto = try Biscuit_Format_Schema_Biscuit(serializedBytes: data)
        proto.rootKeyID = UInt32.max
        let serialized = try proto.serializedData()

        let biscuit = try UnverifiedBiscuit(serializedData: serialized)
        XCTAssertEqual(biscuit.rootKeyID?.value, Int(UInt32.max))
        XCTAssertEqual(try biscuit.serializedData(), serialized)
    }

    func testGetOutOfRangeArrayIndex() throws {
        let array = Value.array(1, 2, 3)
        XCTAssertEqual(try array.opGet(Value(.integer(3))), Value.null)
        XCTAssertEqual(try array.opGet(Value(.integer(-1))), Value.null)
        XCTAssertEqual(try array.opGet(Value(.integer(Int64.min))), Value.null)
        XCTAssertEqual(try array.opGet(Value(.integer(Int64.max))), Value.null)
        XCTAssertEqual(try array.opGet(Value(.integer(0))), Value(1))
    }
}
