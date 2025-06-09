/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A Datalog Expression
public struct Expression: ExpressionConvertible, Sendable, Hashable, CustomStringConvertible {
    let ops: [Op]

    init(proto: Biscuit_Format_Schema_ExpressionV2, interner: BlockInternmentTable) throws {
        self.ops = try proto.ops.map { try Op(proto: $0, interner: interner) }
    }

    init(term: Term) {
        self.ops = [.value(term)]
    }

    init(op: OpUnary, expr: Expression) {
        self.ops = expr.ops + [.unary(op)]
    }

    init(op: OpBinary, lhs: Expression, rhs: Expression) {
        self.ops = lhs.ops + rhs.ops + [.binary(op)]
    }

    init(op: OpBinary, lhs: Expression, rhs: Closure) {
        self.ops = lhs.ops + [.closure(rhs), .binary(op)]
    }

    init(op: OpBinary, lhs: Closure, rhs: Expression) {
        self.ops = [.closure(lhs)] + rhs.ops + [.binary(op)]
    }

    init(parse: Parser.Expression) {
        var ops: [Op] = []
        parseIntoOps(parse, &ops)
        self.ops = ops
    }

    /// A negation expression
    public var negated: Expression {
        Expression(op: .negate, expr: self)
    }

    /// A parentheses expression
    public var parenthesized: Expression {
        Expression(op: .parens, expr: self)
    }

    /// A length expression
    public var length: Expression {
        Expression(op: .length, expr: self)
    }

    /// A greater than expression
    public func greaterThan<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .gt, lhs: self, rhs: rhs.expression)
    }

    /// A greater than or equal expression
    public func greaterThanOrEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .gtEq, lhs: self, rhs: rhs.expression)
    }

    /// A less than expression
    public func lessThan<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .lt, lhs: self, rhs: rhs.expression)
    }

    /// A less than or equal expression
    public func lessThanOrEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .ltEq, lhs: self, rhs: rhs.expression)
    }

    /// An equality expression
    public func equal<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .heterogeneousEqual, lhs: self, rhs: rhs.expression)
    }

    /// A non-equality expression
    public func notEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .heterogeneousNotEqual, lhs: self, rhs: rhs.expression)
    }

    /// A strict equality expression (both sides must have the same type)
    public func strictEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .eq, lhs: self, rhs: rhs.expression)
    }

    /// A strict non-equality expression (both sides must have the same type)
    public func strictNotEqual<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .notEq, lhs: self, rhs: rhs.expression)
    }

    /// An and expression
    public func and<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .lazyAnd, lhs: self, rhs: Closure(body: rhs))
    }

    /// An or expression
    public func or<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .lazyOr, lhs: self, rhs: Closure(body: rhs))
    }

    /// A strict and expression (both sides will be evaluated)
    public func strictAnd<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .and, lhs: self, rhs: rhs.expression)
    }

    /// A strict or expression (both sides with be evaluated)
    public func strictOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .or, lhs: self, rhs: rhs.expression)
    }

    /// An add expression
    public func add<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .add, lhs: self, rhs: rhs.expression)
    }

    /// A substract expression
    public func subtract<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .sub, lhs: self, rhs: rhs.expression)
    }

    /// A multiple expression
    public func multiply<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .mul, lhs: self, rhs: rhs.expression)
    }

    /// A divide expression
    public func divide<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .div, lhs: self, rhs: rhs.expression)
    }

    /// A bitwise and expression
    public func bitwiseAnd<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .bitwiseAnd, lhs: self, rhs: rhs.expression)
    }

    /// A bitwise or expression
    public func bitwiseOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .bitwiseOr, lhs: self, rhs: rhs.expression)
    }

    /// A bitwise xor expression
    public func bitwiseXor<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .bitwiseXor, lhs: self, rhs: rhs.expression)
    }

    /// A contains expression
    public func contains<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .contains, lhs: self, rhs: rhs.expression)
    }

    /// A starts with expression
    public func startsWith<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .startsWith, lhs: self, rhs: rhs.expression)
    }

    /// An ends with expression
    public func endsWith<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .endsWith, lhs: self, rhs: rhs.expression)
    }

    /// A matches expression
    public func matches<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .regex, lhs: self, rhs: rhs.expression)
    }

    /// A set intersection expression
    public func intersection<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .intersection, lhs: self, rhs: rhs.expression)
    }

    /// A union expression
    public func union<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .union, lhs: self, rhs: rhs.expression)
    }

    /// A get expression
    public func get<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .get, lhs: self, rhs: rhs.expression)
    }

    // An any expression
    public func any(_ rhs: Closure) -> Expression {
        Expression(op: .any, lhs: self, rhs: rhs)
    }

    // An all expression
    public func all(_ rhs: Closure) -> Expression {
        Expression(op: .all, lhs: self, rhs: rhs)
    }

    // A try_or expression
    public func tryOr<Rhs: ExpressionConvertible>(_ rhs: Rhs) -> Expression {
        Expression(op: .tryOr, lhs: Closure(body: self), rhs: rhs.expression)
    }
    
    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_ExpressionV2 {
        var proto = Biscuit_Format_Schema_ExpressionV2()
        proto.ops = self.ops.map { $0.proto(interner) }
        return proto
    }

    func evaluate(_ variables: [String: Value]) throws -> Bool {
        var stack: [StackElement] = []
        for op in self.ops {
            switch op {
                case .value(let term):
                    try stack.append(StackElement(term, variables))
                case .unary(let op):
                    guard let arg = stack.popLast() else {
                        throw Biscuit.EvaluationError.invalidUnaryOp
                    }
                    try stack.append(.value(op.evaluate(arg)))
                case .binary(let op):
                    guard let arg2 = stack.popLast() else {
                        throw Biscuit.EvaluationError.invalidBinaryOp
                    }
                    guard let arg1 = stack.popLast() else {
                        throw Biscuit.EvaluationError.invalidBinaryOp
                    }
                    try stack.append(.value(op.evaluate(arg1, arg2, variables)))
                case .closure(let closure):
                    stack.append(.closure(closure))
            }
        }
        if stack.count == 1 {
            if case .value(let val) = stack.popLast() {
                if case .bool(let b) = val.wrapped {
                    return b
                }
            }
            throw Biscuit.EvaluationError.nonBooleanExpression
        } else {
            throw Biscuit.EvaluationError.invalidExpression
        }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        for op in self.ops {
            op.intern(&interner, &locals)
        }
    }

    public var expression: Expression { self }

    public var description: String {
        var offset = self.ops.count
        return printOps(self.ops, &offset)
    }
}

enum Op: Sendable, Hashable {
    case value(Term)
    case unary(OpUnary)
    case binary(OpBinary)
    case closure(Closure)

    init(proto: Biscuit_Format_Schema_Op, interner: BlockInternmentTable) throws {
        self = switch proto.content {
            case .value(let term): try .value(Term(proto: term, interner: interner))
            case .unary(let op_unary): try .unary(OpUnary(proto: op_unary, interner: interner))
            case .binary(let op_binary): try .binary(OpBinary(proto: op_binary, interner: interner))
            case .closure(let op_closure): try .closure(Closure(proto: op_closure, interner: interner))
            case .none: throw Biscuit.ValidationError.missingOp
        }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        switch self {
            case .value(let term): term.intern(&interner, &locals)
            case .closure(let closure): closure.intern(&interner, &locals)
            default: return
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Op {
        var proto = Biscuit_Format_Schema_Op()
        switch self {
            case .value(let term): proto.value = term.proto(interner)
            case .unary(let op_unary): proto.unary = op_unary.proto(interner)
            case .binary(let op_binary): proto.binary = op_binary.proto(interner)
            case .closure(let op_closure): proto.closure = op_closure.proto(interner)
        }
        return proto
    }
}

enum StackElement: Hashable {
    case value(Value)
    case closure(Closure)

    init(_ term: Term, _ variables: [String: Value]) throws {
        switch term.wrapped {
            case .variable(let name):
                guard let concrete = variables[name] else {
                    throw Biscuit.EvaluationError.unknownVariable
                }
                self = .value(concrete)
            case .value(let value): self = .value(value)
        }
    }
}

/// Anything which can be converted into an Expression
public protocol ExpressionConvertible {
    var expression: Expression { get }
}

func parseIntoOps(_ parse: Parser.Expression, _ ops: inout [Op]) {
    switch parse {
        case .term(let term): ops.append(.value(term))
        case .closure(let closure): ops.append(.closure(closure))
        case .unaryOp(let op, let e):
            parseIntoOps(e, &ops)
            ops.append(.unary(op))
        case .binaryOp(let op, let e1, let e2):
            parseIntoOps(e1, &ops)
            parseIntoOps(e2, &ops)
            ops.append(.binary(op))
    }
}

func printOps(_ ops: [Op], _ offset: inout Int, _ isLazy: Bool = false) -> String {
    offset -= 1
    switch ops[offset] {
        case .value(let term): return term.description
        case .closure(let closure): return isLazy ? closure.bodyDescription : closure.description
        case .binary(let op):
            let e2 = printOps(ops, &offset, op == .lazyAnd || op == .lazyOr)
            let e1 = printOps(ops, &offset, op == .tryOr)
            return switch op {
                case .gt: "\(e1) > \(e2)"
                case .gtEq: "\(e1) >= \(e2)"
                case .lt: "\(e1) < \(e2)"
                case .ltEq: "\(e1) <= \(e2)"
                case .eq: "\(e1) === \(e2)"
                case .notEq: "\(e1) !== \(e2)"
                case .and: "\(e1) && \(e2)"
                case .or: "\(e1) || \(e2)"
                case .add: "\(e1) + \(e2)"
                case .sub: "\(e1) - \(e2)"
                case .mul: "\(e1) * \(e2)"
                case .div: "\(e1) / \(e2)"
                case .bitwiseAnd: "\(e1) & \(e2)"
                case .bitwiseOr: "\(e1) | \(e2)"
                case .bitwiseXor: "\(e1) ^ \(e2)"
                case .contains: "\(e1).contains(\(e2))"
                case .startsWith: "\(e1).starts_with(\(e2))"
                case .endsWith: "\(e1).ends_with(\(e2))"
                case .regex: "\(e1).matches(\(e2))"
                case .intersection: "\(e1).intersection(\(e2))"
                case .union: "\(e1).union(\(e2))"
                case .heterogeneousEqual: "\(e1) == \(e2)"
                case .heterogeneousNotEqual: "\(e1) != \(e2)"
                case .lazyAnd: "\(e1) && \(e2)"
                case .lazyOr: "\(e1) || \(e2)"
                case .any: "\(e1).any(\(e2))"
                case .all: "\(e1).all(\(e2))"
                case .get: "\(e1).get(\(e2))"
                case .ffi(let name): "\(e1).extern::\(name)(\(e2))"
                case .tryOr: "\(e1).tryOr(\(e2))"
            }
        case .unary(let op):
            let e = printOps(ops, &offset)
            return switch op {
                case .negate: "!\(e)"
                case .length: "\(e).length()"
                case .typeOf: "\(e).type()"
                case .ffi(let name): "\(e).extern::\(name)()"
                case .parens: "(\(e))"
            }
    }
}
