/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
/// A Datalog Closure
///
/// Closures appear as arguments to certain Datalog `Expression`s, such as `any` and `all`
public struct Closure: Sendable, Hashable, CustomStringConvertible {
    let params: [String]
    let ops: [Op]

    /// Construct a closure
    /// - Parameter parameter: the names of this closure's parameter variables
    /// - Parameter body: the body of this closure
    public init<E: ExpressionConvertible>(_ parameters: String..., body: E) {
        self.params = parameters
        self.ops = body.expression.ops
    }

    init(proto: Biscuit_Format_Schema_OpClosure, interner: BlockInternmentTable) throws {
        self.params = try proto.params.map { try interner.lookupSymbol(Int($0)) }
        self.ops = try proto.ops.map { try Op(proto: $0, interner: interner) }
    }

    init(params: [String], body: Parser.Expression) {
        self.params = params
        var ops: [Op] = []
        parseIntoOps(body, &ops)
        self.ops = ops
    }

    func opTryOr(_ alternative: Value, _ variables: [String: Value]) throws -> Value {
        do {
            return try self.evaluate(variables)
        } catch let e as Biscuit.EvaluationError where e == Biscuit.EvaluationError.typeError {
            return alternative
        }
    }

    func evaluate(_ variables: [String: Value]) throws -> Value {
        guard params.count == 0 else {
            throw Biscuit.EvaluationError.wrongArity
        }
        return try self.evaluateInner(variables)
    }

    func evaluate(_ arg: Value, _ variables: [String: Value]) throws -> Value {
        guard params.count == 1 else {
            throw Biscuit.EvaluationError.wrongArity
        }
        guard !variables.keys.contains(params[0]) else {
            throw Biscuit.EvaluationError.variableShadowing
        }
        var variables = variables
        variables[params[0]] = arg
        return try self.evaluateInner(variables)
    }

    func evaluateInner(_ variables: [String: Value]) throws -> Value {
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
            if case .value(let value) = stack.popLast() {
                return value
            } else {
                throw Biscuit.EvaluationError.closureEvaluatedToClosure
            }
        } else {
            throw Biscuit.EvaluationError.invalidExpression
        }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        for param in self.params {
            interner.intern(param, &locals)
        }
        for op in self.ops {
            op.intern(&interner, &locals)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_OpClosure {
        var proto = Biscuit_Format_Schema_OpClosure()
        proto.params = self.params.map { UInt32(interner.symbolIndex(for: $0)) }
        proto.ops = self.ops.map { $0.proto(interner) }
        return proto
    }

    var bodyDescription: String {
        var offset = self.ops.count
        return printOps(self.ops, &offset)
    }

    public var description: String {
        let params = self.params.map { "$\($0)" }.joined(separator: ", ")
        let body = self.bodyDescription
        return "\(params) -> \(body)"
    }
}
