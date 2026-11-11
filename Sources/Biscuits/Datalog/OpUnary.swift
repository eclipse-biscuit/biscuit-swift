/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
enum OpUnary: Sendable, Hashable {
    case negate, parens, length, typeOf
    case ffi(String)

    init(
        proto: Biscuit_Format_Schema_OpUnary,
        interner: InternmentTable,
        limits: Biscuit.DeserializationLimits.PerBlock
    ) throws {
        guard proto.hasKind else {
            throw Biscuit.ValidationError.missingOp
        }
        if let allowedOperations = limits.allowedUnaryOperations {
            guard allowedOperations.contains(Biscuit.UnaryOperation(kind: proto.kind)) else {
                throw Biscuit.DeserializationLimitError.unaryOperationNotAllowed
            }
        }
        switch proto.kind {
        case .negate: self = .negate
        case .parens: self = .parens
        case .length: self = .length
        case .typeOf: self = .typeOf
        case .ffi:
            guard proto.hasFfiName else {
                throw Biscuit.ValidationError.missingFFI
            }
            let name = try interner.lookupSymbol(proto.ffiName)
            guard name.utf8.count <= limits.maximumNameLength else {
                throw Biscuit.DeserializationLimitError.nameTooLong
            }
            if let allowedFunctions = limits.allowedUnaryExternalFunctions {
                guard allowedFunctions.contains(name) else {
                    throw Biscuit.DeserializationLimitError.externalFunctionNotAllowed
                }
            }
            self = .ffi(name)
        }
    }

    func intern(_ interner: inout InternmentTable, _ locals: inout [String]) -> Biscuit_Format_Schema_OpUnary {
        var proto = Biscuit_Format_Schema_OpUnary()
        switch self {
        case .negate: proto.kind = .negate
        case .parens: proto.kind = .parens
        case .length: proto.kind = .length
        case .typeOf: proto.kind = .typeOf
        case .ffi(let name):
            proto.ffiName = UInt64(interner.intern(name, &locals))
            proto.kind = .ffi
        }
        return proto
    }

    func evaluate(_ arg: StackElement) throws -> Value {
        switch (self, arg) {
        case (.parens, .value(let v)): return v
        case (.negate, .value(let v)): return try v.opNegate()
        case (.length, .value(let v)): return try v.opLength()
        case (.typeOf, .value(let v)): return v.type.value
        case (.ffi(let name), _): throw Biscuit.EvaluationError.unknownForeignFunction(name)
        default: throw Biscuit.EvaluationError.typeError
        }
    }
}
