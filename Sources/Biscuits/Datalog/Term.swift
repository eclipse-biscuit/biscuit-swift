/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A term which can be used as part of a `Fact` or as an expression
public struct Term: TermConvertible, ExpressionConvertible, Sendable, Hashable, CustomStringConvertible {
    internal enum Wrapped: Hashable {
        case variable(String)
        case value(Value)
    }
    let wrapped: Wrapped

    /// A variable term
    /// - Parameter variable: The name of this variable
    public init(variable: String) {
        self.wrapped = .variable(variable)
    }

    /// A literal value
    /// - Parameter value: The value of this Term
    public init<V: ValueConvertible>(value: V) {
        self.wrapped = .value(value.value)
    }

    init(proto: Biscuit_Format_Schema_Term, interner: BlockInternmentTable) throws {
        self.wrapped =
            switch proto.content {
            case .variable(let v): try .variable(interner.lookupSymbol(Int(v)))
            default: try .value(Value(proto: proto, interner: interner))
            }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        switch self.wrapped {
        case .variable(let name): interner.intern(name, &locals)
        case .value(let term): term.intern(&interner, &locals)
        }
    }

    func makeConcrete(variables: [String: Value]) throws -> Value {
        switch self.wrapped {
        case .variable(let name):
            guard let term = variables[name] else {
                throw Biscuit.EvaluationError.unknownVariable
            }
            return term
        case .value(let term): return term
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Term {
        var proto = Biscuit_Format_Schema_Term()
        switch self.wrapped {
        case .variable(let v): proto.variable = UInt32(interner.symbolIndex(for: v))
        case .value(let term): return term.proto(interner)
        }
        return proto
    }

    var isConcrete: Bool {
        switch self.wrapped {
        case .value: true
        case .variable: false
        }
    }

    var value: Value? {
        switch self.wrapped {
        case .value(let v): v
        case .variable: nil
        }
    }

    public var term: Term { self }

    public var description: String {
        switch self.wrapped {
        case .variable(let name): "$\(name)"
        case .value(let term): term.description
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
}

/// Anything which can be converted into a Term
public protocol TermConvertible: ExpressionConvertible {
    var term: Term { get }
}

extension TermConvertible {
    public var expression: Expression { Expression(term: self.term) }
}

extension ValueConvertible {
    public var term: Term { Term(value: self.value) }
}
