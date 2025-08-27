/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
enum OpUnary: Sendable, Hashable {
    case negate, parens, length, typeOf
    case ffi(String)

    init(proto: Biscuit_Format_Schema_OpUnary, interner: BlockInternmentTable) throws {
        guard proto.hasKind else {
            throw Biscuit.ValidationError.missingOp
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
            self = try .ffi(interner.lookupSymbol(Int(proto.ffiName)))
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_OpUnary {
        var proto = Biscuit_Format_Schema_OpUnary()
        switch self {
        case .negate: proto.kind = .negate
        case .parens: proto.kind = .parens
        case .length: proto.kind = .length
        case .typeOf: proto.kind = .typeOf
        case .ffi(let s):
            proto.ffiName = UInt64(interner.symbolIndex(for: s))
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
