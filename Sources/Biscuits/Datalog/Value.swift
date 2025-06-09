/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A Datalog literal value; a `Term` which is not a variable
public struct Value: ValueConvertible, TermConvertible, ExpressionConvertible, Sendable, Hashable, CustomStringConvertible {
    enum Wrapped: Hashable {
        case integer(Int64)
        case string(String)
        case date(Date)
        case bytes(Data)
        case bool(Bool)
        case set(Set<Value>)
        case null
        case array([Value])
        case map([MapKey: Value])
    }
    var wrapped: Wrapped

    /// An integer Value
    public init(_ integer: Int) {
        self.wrapped = .integer(Int64(integer))
    }

    /// A string Value
    public init(_ string: String) {
        self.wrapped = .string(string)
    }

    /// A date Value
    public init(_ date: Date) {
        self.wrapped = .date(date)
    }

    /// A byte array Value
    public init(_ bytes: Data) {
        self.wrapped = .bytes(bytes)
    }

    /// A boolean Value
    public init(_ bool: Bool) {
        self.wrapped = .bool(bool)
    }

    /// The null Value
    public static var null: Value { Value() }

    /// The empty set Value
    public static var emptySet: Value { Value(.set([])) }

    /// The empty array Value
    public static var emptyArray: Value { Value(.array([])) }

    /// The empty map Value
    public static var emptyMap: Value { Value(.map([:])) }

    /// Construct a bytes Value from a hexadecimal-encoded string
    ///
    /// - Parameter hexString: a hexadecimal encoded bytes literal
    /// - Returns: a bytes value
    /// - Throws: Throws a `DatalogError` if the string contains non-hexadecimal characters
    public static func bytes(hexString: String) throws -> Value {
        if let bytes = hexDecode(hexString[...]) {
            return Value(bytes)
        } else {
            throw Biscuit.DatalogError.invalidHexData
        }
    }

    /// Construct a set value from a set of values
    ///
    /// Set values cannot contain other sets as elements
    /// - Parameter from: a set of values
    /// - Returns: a value which is a set
    /// - Throws: Throws a `DatalogError` if one of the values is a set
    public static func set<V: ValueConvertible>(from set: Set<V>) throws -> Value {
        return try Value(.set(Set<Value>(set.map {
            let elem = $0.value
            if case .set = elem.wrapped {
                throw Biscuit.DatalogError.setInSet
            }
            return elem
        })))
    }

    /// Construct a set value from variadic value arguments
    ///
    /// Set values cannot contain other sets as elements
    /// - Parameter value: a value in the set
    /// - Returns: a value which is a set
    /// - Throws: Throws a `DatalogError` if one of the values is a set
    public static func set<each V: ValueConvertible>(_ value: repeat each V) throws -> Value {
        func tryInsert(_ values: inout Set<Value>, _ elem: Value) throws {
            if case .set = elem.wrapped {
                throw Biscuit.DatalogError.setInSet
            }
            _ = values.insert(elem)
        }
        var values: Set<Value> = []
        repeat try tryInsert(&values, (each value).value)
        return Value(.set(values))
    }

    /// Construct an array value from an array of values
    /// - Parameter from: an array of values
    /// - Returns: a value which is an array
    public static func array<V: ValueConvertible>(from array: [V]) -> Value {
        return Value(.array(array.map { $0.value }))
    }

    /// Construct an array value from variadic value arguments
    /// - Parameter value: a value in the array
    /// - Returns: a value which is an array
    public static func array<each V: ValueConvertible>(_ value: repeat each V) -> Value {
        var values: [Value] = []
        repeat values.append((each value).value)
        return Value(.array(values))
    }

    /// Construct a map value from  a Dictionary of map keys and values
    /// - Parameter from: a dictionary of map keys to values
    /// - Returns: a value which is a map
    /// - Throws: Throws a `DatalogError` if multiple different values are assigned to the same mapkey
    public static func map<K: MapKeyConvertible, V: ValueConvertible>(from map: [K: V]) throws -> Value {
        return try Value(.map(Dictionary(map.map {
            ($0.mapKey, $1.value)
        }, uniquingKeysWith: { v1, v2 in 
            guard v1 == v2 else { throw  Biscuit.DatalogError.duplicateMapKey }
            return v1
        })))
    }

    /// Construct a map value from variadic key and value arguments
    /// - Parameter pair: a tuple of a map key and a value that will be in the map
    /// - Returns: a value which is a map
    /// - Throws: Throws a `DatalogError` if multiple different values are assigned to the same mapkey
    public static func map<each K: MapKeyConvertible, each V: ValueConvertible>(_ pair: repeat (each K, each V)) throws -> Value {
        func tryInsert(_ values: inout [MapKey: Value], _ key: MapKey, _ value: Value) throws {
            if let existingValue = values[key] {
                if existingValue != value {
                    throw Biscuit.DatalogError.duplicateMapKey
                }
            } else {
                values[key] = value
            }
        }
        var values: [MapKey: Value] = [:]
        repeat try tryInsert(&values, (each pair).0.mapKey, (each pair).1.value)
        return Value(.map(values))
    }

    init() {
        self.wrapped = .null
    }

    init(_ wrapped: Wrapped) {
        self.wrapped = wrapped
    }

    init(proto: Biscuit_Format_Schema_TermV2, interner: BlockInternmentTable) throws {
        self.wrapped = switch proto.content {
            case .integer(let i): .integer(i)
            case .string(let s): try .string(interner.lookupSymbol(Int(s)))
            case .date(let d): .date(Date(timeIntervalSince1970: TimeInterval(d)))
            case .bytes(let b): .bytes(b)
            case .bool(let b): .bool(b)
            case .set(let terms): try .set(Set(terms.set.map {
                let value = try Value(proto: $0, interner: interner)
                if case .set = value.wrapped {
                    throw Biscuit.ValidationError.setInSet
                }
                return value
            }))
            case .array(let terms): try .array(terms.array.map { try Value(proto: $0, interner: interner) })
            case .map(let terms):
                try .map(Dictionary(terms.entries.map {
                    let key = try MapKey(proto: $0.key, interner: interner)
                    let val = try Value(proto: $0.value, interner: interner)
                    return (key, val)
                }, uniquingKeysWith: { v1, v2 in 
                    guard v1 == v2 else { throw  Biscuit.ValidationError.duplicateMapKey }
                    return v1
                }))
            case .null: .null
            case .variable: throw Biscuit.ValidationError.variableInFact
            case .none: throw Biscuit.ValidationError.missingTerm
        }
    }

    // Intentionally not public and Value does not conform to Comparable
    static func < (lhs: Value, rhs: Value) -> Bool {
        switch (lhs.wrapped, rhs.wrapped) {
            case (.integer(let l), .integer(let r)): return l < r
            case (.string(let l), .string(let r)): return l < r
            case (.date(let l), .date(let r)): return l < r
            case (.bytes(let l), .bytes(let r)):
                guard l.count <= r.count else { return false }
                return zip(l, r).allSatisfy { $0 < $1 }
            case (.bool(let l), .bool(let r)): return !l && r
            case (.set(let l), .set(let r)):
                guard l.count <= r.count else { return false }
                return zip(l.sorted(by: <), r.sorted(by: <)).allSatisfy { $0 < $1 }
            case (.null, .null): return false
            case (.array(let l), .array(let r)):
                guard l.count <= r.count else { return false }
                return zip(l, r).allSatisfy { $0 < $1 }
            case (.map(let l), .map(let r)):
                guard l.count <= r.count else { return false }
                return zip(l.sorted(by: { $0.0 < $1.0 }), r.sorted(by: { $0.0 < $1.0 })).allSatisfy { $0.1 < $1.1 }
            case (.integer, _): return true
            case (_, .integer): return false
            case (.string, _): return true
            case (_, .string): return false
            case (.date, _): return true
            case (_, .date): return false
            case (.bytes, _): return true
            case (_, .bytes): return false
            case (.bool, _): return true
            case (_, .bool): return false
            case (.set, _): return true
            case (_, .set): return false
            case (.null, _): return true
            case (_, .null): return false
            case (.array, _): return true
            case (_, .array): return false
        }
    }

    /// A negation expression
    public var negated: Expression {
        self.expression.negated
    }

    /// A parentheses expression
    public var parenthesized: Expression {
        self.expression.parenthesized
    }

    /// A length expression
    public var length: Expression {
        self.expression.length
    }

    /// A greater than expression
    public func greaterThan<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.greaterThan(rhs)
    }

    /// A greater than or equal expression
    public func greaterThanOrEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.greaterThanOrEqual(rhs)
    }

    /// A less than expression
    public func lessThan<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.lessThan(rhs)
    }

    /// A less than or equal expression
    public func lessThanOrEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.lessThanOrEqual(rhs)
    }

    /// An equality expression
    public func equal<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.equal(rhs)
    }

    /// A non-equality expression
    public func notEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.notEqual(rhs)
    }

    /// A strict equality expression (both sides must have the same type)
    public func strictEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.strictEqual(rhs)
    }

    /// A strict non-equality expression (both sides must have the same type)
    public func strictNotEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.strictNotEqual(rhs)
    }

    /// An and expression
    public func and<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.and(rhs)
    }

    /// An or expression
    public func or<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.or(rhs)
    }

    /// A strict and expression (both sides will be evaluated)
    public func strictAnd<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.strictAnd(rhs)
    }

    /// A strict or expression (both sides with be evaluated)
    public func strictOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.strictOr(rhs)
    }


    /// An add expression
    public func add<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.add(rhs)
    }

    /// A substract expression
    public func subtract<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.subtract(rhs)
    }

    /// A multiple expression
    public func multiply<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.multiply(rhs)
    }

    /// A divide expression
    public func divide<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.divide(rhs)
    }

    /// A bitwise and expression
    public func bitwiseAnd<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.bitwiseAnd(rhs)
    }

    /// A bitwise or expression
    public func bitwiseOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.bitwiseOr(rhs)
    }

    /// A bitwise xor expression
    public func bitwiseXor<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.bitwiseXor(rhs)
    }

    /// A contains expression
    public func contains<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.contains(rhs)
    }

    /// A starts with expression
    public func startsWith<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.startsWith(rhs)
    }

    /// An ends with expression
    public func endsWith<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.endsWith(rhs)
    }

    /// A matches expression
    public func matches<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.matches(rhs)
    }

    /// A set intersection expression
    public func intersection<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.intersection(rhs)
    }

    /// A union expression
    public func union<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.union(rhs)
    }

    /// A get expression
    public func get<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.get(rhs)
    }

    // An any expression
    public func any(_ rhs: Closure) -> Expression {
        self.expression.any(rhs)
    }

    // An all expression
    public func all(_ rhs: Closure) -> Expression {
        self.expression.all(rhs)
    }

    // A try_or expression
    public func tryOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        self.expression.tryOr(rhs)
    }


    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        switch self.wrapped {
            case .string(let string):
                interner.intern(string, &locals)
            case .set(let set):
                for term in set.sorted(by: <) {
                    term.intern(&interner, &locals)
                }
            case .array(let array):
                for term in array {
                    term.intern(&interner, &locals)
                }
            case .map(let map):
                for (key, val) in map.sorted(by: { $0.0 < $1.0 }) {
                    key.intern(&interner, &locals)
                    val.intern(&interner, &locals)
                }
            default: return
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_TermV2 {
        var proto = Biscuit_Format_Schema_TermV2()
        switch self.wrapped {
            case .integer(let i): proto.integer = Int64(i)
            case .string(let s): proto.string = UInt64(interner.symbolIndex(for: s))
            case .date(let d): proto.date = UInt64(d.timeIntervalSince1970)
            case .bytes(let b): proto.bytes = b
            case .bool(let b): proto.bool = b
            case .set(let terms):
                proto.set = Biscuit_Format_Schema_TermSet()
                proto.set.set = terms.map { $0.proto(interner) }.sorted(by: <)
            case .array(let terms):
                proto.array = Biscuit_Format_Schema_Array()
                proto.array.array = terms.map { $0.proto(interner) }
            case .map(let terms):
                proto.map = Biscuit_Format_Schema_Map()
                proto.map.entries = terms.map {
                    var entry = Biscuit_Format_Schema_MapEntry()
                    entry.key = $0.proto(interner)
                    entry.value = $1.proto(interner)
                    return entry
                }.sorted(by: <)
            case .null: proto.null = Biscuit_Format_Schema_Empty()
        }
        return proto
    }

    public var value: Value { self }

    public var description: String {
        switch self.wrapped {
            case .integer(let int): "\(int)"
            case .string(let string): "\"\(string)\""
            case .date(let date): "\(date)"
            case .bytes(let bytes): "hex:\(bytes.map { String(format: "%02hhx", $0) }.joined())"
            case .bool(let bool): "\(bool)"
            case .set(let set): "{\(set.sorted(by: <).map { "\($0)" }.joined(separator: ", "))}"
            case .array(let array): "[\(array.map { "\($0)" }.joined(separator: ", "))]"
            case .map(let dict): "{\(dict.sorted(by: { $0.0 < $1.0 }).map { "\($0): \($1)" }.joined(separator: ", "))}"
            case .null: "null"
        }
    }

    var type: String {
        switch self.wrapped {
            case .integer: "integer"
            case .string: "string"
            case .bytes: "bytes"
            case .bool: "bool"
            case .date: "date"
            case .array: "array"
            case .map: "map"
            case .null: "null"
            case .set: "set"
        }
    }

    func opNegate() throws -> Value {
        switch self.wrapped {
            case .bool(let x): return Value(!x)
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opLength() throws -> Value {
        switch self.wrapped {
            case .string(let x): return x.utf8.count.value
            case .bytes(let x): return x.count.value
            case .set(let x): return x.count.value
            case .array(let x): return x.count.value
            case .map(let x): return x.count.value
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opLt(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(x < y)
            case (.date(let x), .date(let y)): Value(x < y)
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opGt(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(x > y)
            case (.date(let x), .date(let y)): Value(x > y)
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opLtEq(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(x <= y)
            case (.date(let x), .date(let y)): Value(x <= y)
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opGtEq(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(x >= y)
            case (.date(let x), .date(let y)): Value(x >= y)
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opEq(_ rhs: Value) throws -> Value {
        guard self.type == rhs.type else {
            throw Biscuit.EvaluationError.typeError
        }
        return Value(self == rhs)
    }

    func opNotEq(_ rhs: Value) throws -> Value {
        guard self.type == rhs.type else {
            throw Biscuit.EvaluationError.typeError
        }
        return Value(self != rhs)
    }

    func opContains(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.string(let x), .string(let y)): Value(x.contains(y))
            case (.set(let x), .set(let y)): Value(x.isSuperset(of: y))
            case (.set(let x), _): Value(x.contains(rhs))
            case (.array(let x), _): Value(x.contains(rhs))
            case (.map(let x), .integer(let y)): Value(x.keys.contains(MapKey(.integer(y))))
            case (.map(let x), .string(let y)): Value(x.keys.contains(MapKey(y)))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opStartsWith(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.array(let x), .array(let y)): Value(x.starts(with: y))
            case (.string(let x), .string(let y)): Value(x.hasPrefix(y))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opEndsWith(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.array(let x), .array(let y)): Value(x.reversed().starts(with: y.reversed()))
            case (.string(let x), .string(let y)): Value(x.hasSuffix(y))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opAdd(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.string(let x), .string(let y)): return Value(x + y)
            case (.integer(let x), .integer(let y)):
                let (res, overflow) = x.addingReportingOverflow(y)
                if overflow {
                    throw Biscuit.EvaluationError.integerOverflow
                }
                return Value(.integer(res))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opSub(_ rhs: Value) throws -> Value {
        guard case (.integer(let x), .integer(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        let (res, overflow) = x.subtractingReportingOverflow(y)
        if overflow {
            throw Biscuit.EvaluationError.integerOverflow
        }
        return Value(.integer(res))
    }

    func opMul(_ rhs: Value) throws -> Value {
        guard case (.integer(let x), .integer(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        let (res, overflow) = x.multipliedReportingOverflow(by: y)
        if overflow {
            throw Biscuit.EvaluationError.integerOverflow
        }
        return Value(.integer(res))
    }

    func opDiv(_ rhs: Value) throws -> Value {
        guard case (.integer(let x), .integer(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        let (res, overflow) = x.dividedReportingOverflow(by: y)
        if overflow {
            throw Biscuit.EvaluationError.integerOverflow
        }
        return Value(.integer(res))
    }

    func opBitwiseAnd(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(.integer(x & y))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opBitwiseOr(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(.integer(x | y))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opBitwiseXor(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.integer(let x), .integer(let y)): Value(.integer(x ^ y))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opIntersection(_ rhs: Value) throws -> Value {
        guard case (.set(let x), .set(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        return try Value.set(from: x.intersection(y))
    }

    func opUnion(_ rhs: Value) throws -> Value {
        guard case (.set(let x), .set(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        return try Value.set(from: x.union(y))
    }

    func opRegex(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.string(let x), .string(let y)): return try Value(x.contains(Regex(y)))
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opGet(_ rhs: Value) throws -> Value {
        switch (self.wrapped, rhs.wrapped) {
            case (.array(let array), .integer(let i)):
                return array.count > i ? array[Int(i)] : Value.null
            case (.map(let map), .integer(let x)):
                return map[MapKey(.integer(x))] ?? Value.null
            case (.map(let map), .string(let x)):
                return map[MapKey(x)] ?? Value.null
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opAny(_ f: Closure, _ vars: [String: Value]) throws -> Value {
        switch self.wrapped {
            case .set(let x): return try x.contains() { try f.evaluate($0, vars) == true.value }.value
            case .array(let x): return try x.contains() { try f.evaluate($0, vars) == true.value }.value
            case .map(let x): return try x.contains() { try f.evaluate(Value.array($0, $1), vars) == true.value }.value
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opAll(_ f: Closure, _ vars: [String: Value]) throws -> Value {
        switch self.wrapped {
            case .set(let x): return try x.allSatisfy() { try f.evaluate($0, vars) == true.value }.value
            case .array(let x): return try x.allSatisfy() { try f.evaluate($0, vars) == true.value }.value
            case .map(let x): return try x.allSatisfy() { try f.evaluate(Value.array($0, $1), vars) == true.value }.value
            default: throw Biscuit.EvaluationError.typeError
        }
    }

    func opAnd(_ rhs: Value) throws -> Value {
        guard case (.bool(let x), .bool(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        return Value(x && y)
    }

    func opOr(_ rhs: Value) throws -> Value {
        guard case (.bool(let x), .bool(let y)) = (self.wrapped, rhs.wrapped) else {
            throw Biscuit.EvaluationError.typeError
        }
        return Value(x || y)
    }

    func opLazyAnd(_ f: Closure, _ vars: [String: Value]) throws -> Value {
        guard case .bool(let x) = self.wrapped else {
            throw Biscuit.EvaluationError.typeError
        }
        guard x else { return false.value }
        let value = try f.evaluate(vars)
        guard case .bool = value.wrapped else {
            throw Biscuit.EvaluationError.typeError
        }
        return value
    }

    func opLazyOr(_ f: Closure, _ vars: [String: Value]) throws -> Value {
        guard case .bool(let x) = self.wrapped else {
            throw Biscuit.EvaluationError.typeError
        }
        guard !x else { return true.value }
        let value = try f.evaluate(vars)
        guard case .bool = value.wrapped else {
            throw Biscuit.EvaluationError.typeError
        }
        return value
    }
}

extension Biscuit_Format_Schema_TermV2: Comparable {
    static func < (lhs: Biscuit_Format_Schema_TermV2, rhs: Biscuit_Format_Schema_TermV2) -> Bool {
        switch (lhs.content, rhs.content) {
            case (.variable(let l), .variable(let r)): return l < r
            case (.integer(let l), .integer(let r)): return l < r
            case (.string(let l), .string(let r)): return l < r
            case (.date(let l), .date(let r)): return l < r
            case (.bytes(let l), .bytes(let r)):
                guard l.count <= r.count else { return false }
                return zip(l, r).allSatisfy { $0 < $1 }
            case (.bool(let l), .bool(let r)): return !l && r
            case (.set(let l), .set(let r)):
                guard l.set.count <= r.set.count else { return false }
                return zip(l.set.sorted(), r.set.sorted()).allSatisfy { $0 < $1 }
            case (.null, .null): return false
            case (.array(let l), .array(let r)):
                guard l.array.count <= r.array.count else { return false }
                return zip(l.array, r.array).allSatisfy { $0 < $1 }
            case (.map(let l), .map(let r)):
                guard l.entries.count <= r.entries.count else { return false }
                return zip(l.entries.sorted(), r.entries.sorted()).allSatisfy { $0 < $1 }
            case (.none, _): return true
            case (_, .none): return false
            case (.variable, _): return true
            case (_, .variable): return false
            case (.integer, _): return true
            case (_, .integer): return false
            case (.string, _): return true
            case (_, .string): return false
            case (.date, _): return true
            case (_, .date): return false
            case (.bytes, _): return true
            case (_, .bytes): return false
            case (.bool, _): return true
            case (_, .bool): return false
            case (.set, _): return true
            case (_, .set): return false
            case (.null, _): return true
            case (_, .null): return false
            case (.array, _): return true
            case (_, .array): return false
        }
    }
}

/// Anything which can be converted into a Value
public protocol ValueConvertible: TermConvertible {
    var value: Value { get }
}

extension Int: ValueConvertible, TermConvertible, ExpressionConvertible {
    public var value: Value { Value(self) }
}

extension String: ValueConvertible, TermConvertible, ExpressionConvertible {
    public var value: Value { Value(self) }
}

extension Date: ValueConvertible, TermConvertible, ExpressionConvertible {
    public var value: Value { Value(self) }
}

extension Data: ValueConvertible, TermConvertible, ExpressionConvertible {
    public var value: Value { Value(self) }
}

extension Bool: ValueConvertible, TermConvertible, ExpressionConvertible {
    public var value: Value { Value(self) }
}
