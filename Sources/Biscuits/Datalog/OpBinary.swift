/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

enum OpBinary: Sendable, Hashable {
    case gt, lt, gtEq, ltEq, eq, notEq
    case and, or
    case add, sub, mul, div
    case bitwiseAnd, bitwiseOr, bitwiseXor
    case contains, startsWith, endsWith, regex, intersection, union
    case heterogeneousEqual, heterogeneousNotEqual
    case lazyOr, lazyAnd
    case any, all, get
    case ffi(String)
    case tryOr

    init(proto: Biscuit_Format_Schema_OpBinary, interner: BlockInternmentTable) throws {
        guard proto.hasKind else {
            throw Biscuit.ValidationError.missingOp
        }
        switch proto.kind {
        case .greaterThan: self = .gt
        case .lessThan: self = .lt
        case .greaterOrEqual: self = .gtEq
        case .lessOrEqual: self = .ltEq
        case .equal: self = .eq
        case .notEqual: self = .notEq
        case .contains: self = .contains
        case .prefix: self = .startsWith
        case .suffix: self = .endsWith
        case .regex: self = .regex
        case .add: self = .add
        case .sub: self = .sub
        case .mul: self = .mul
        case .div: self = .div
        case .and: self = .and
        case .or: self = .or
        case .intersection: self = .intersection
        case .union: self = .union
        case .bitwiseAnd: self = .bitwiseAnd
        case .bitwiseOr: self = .bitwiseOr
        case .bitwiseXor: self = .bitwiseXor
        case .heterogeneousEqual: self = .heterogeneousEqual
        case .heterogeneousNotEqual: self = .heterogeneousNotEqual
        case .lazyOr: self = .lazyOr
        case .lazyAnd: self = .lazyAnd
        case .any: self = .any
        case .all: self = .all
        case .get: self = .get
        case .ffi:
            guard proto.hasFfiName else {
                throw Biscuit.ValidationError.missingFFI
            }
            self = try .ffi(interner.lookupSymbol(Int(proto.ffiName)))
        case .tryOr: self = .tryOr
        }
    }

    var precedence: Int {
        switch self {
        case .contains, .startsWith, .endsWith, .regex, .intersection, .union, .any, .all: 0
        case .get, .ffi, .tryOr: 0
        case .or, .lazyOr: 1
        case .and, .lazyAnd: 2
        case .gt, .lt, .gtEq, .ltEq, .eq, .notEq, .heterogeneousEqual, .heterogeneousNotEqual: 3
        case .bitwiseXor: 4
        case .bitwiseOr: 5
        case .bitwiseAnd: 6
        case .add, .sub: 7
        case .mul, .div: 8
        }
    }

    var leftAssociative: Bool {
        switch self {
        case .gt, .lt, .gtEq, .ltEq, .eq, .notEq: false
        default: true
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_OpBinary {
        var proto = Biscuit_Format_Schema_OpBinary()
        switch self {
        case .lt: proto.kind = .lessThan
        case .gt: proto.kind = .greaterThan
        case .ltEq: proto.kind = .lessOrEqual
        case .gtEq: proto.kind = .greaterOrEqual
        case .eq: proto.kind = .equal
        case .notEq: proto.kind = .notEqual
        case .contains: proto.kind = .contains
        case .startsWith: proto.kind = .prefix
        case .endsWith: proto.kind = .suffix
        case .regex: proto.kind = .regex
        case .add: proto.kind = .add
        case .sub: proto.kind = .sub
        case .mul: proto.kind = .mul
        case .div: proto.kind = .div
        case .and: proto.kind = .and
        case .or: proto.kind = .or
        case .intersection: proto.kind = .intersection
        case .union: proto.kind = .union
        case .bitwiseAnd: proto.kind = .bitwiseAnd
        case .bitwiseOr: proto.kind = .bitwiseOr
        case .bitwiseXor: proto.kind = .bitwiseXor
        case .heterogeneousEqual: proto.kind = .heterogeneousEqual
        case .heterogeneousNotEqual: proto.kind = .heterogeneousNotEqual
        case .lazyOr: proto.kind = .lazyOr
        case .lazyAnd: proto.kind = .lazyAnd
        case .any: proto.kind = .any
        case .all: proto.kind = .all
        case .get: proto.kind = .get
        case .ffi(let s):
            proto.ffiName = UInt64(interner.symbolIndex(for: s))
            proto.kind = .ffi
        case .tryOr: proto.kind = .tryOr
        }
        return proto
    }

    func evaluate(_ arg1: StackElement, _ arg2: StackElement, _ variables: [String: Value]) throws -> Value {
        switch (self, arg1, arg2) {
        case (.lt, .value(let x), .value(let y)): return try x.opLt(y)
        case (.gt, .value(let x), .value(let y)): return try x.opGt(y)
        case (.ltEq, .value(let x), .value(let y)): return try x.opLtEq(y)
        case (.gtEq, .value(let x), .value(let y)): return try x.opGtEq(y)
        case (.eq, .value(let x), .value(let y)): return try x.opEq(y)
        case (.notEq, .value(let x), .value(let y)): return try x.opNotEq(y)
        case (.heterogeneousEqual, .value(let x), .value(let y)): return Value(x == y)
        case (.heterogeneousNotEqual, .value(let x), .value(let y)): return Value(x != y)
        case (.contains, .value(let x), .value(let y)): return try x.opContains(y)
        case (.startsWith, .value(let x), .value(let y)): return try x.opStartsWith(y)
        case (.endsWith, .value(let x), .value(let y)): return try x.opEndsWith(y)
        case (.add, .value(let x), .value(let y)): return try x.opAdd(y)
        case (.sub, .value(let x), .value(let y)): return try x.opSub(y)
        case (.mul, .value(let x), .value(let y)): return try x.opMul(y)
        case (.div, .value(let x), .value(let y)): return try x.opDiv(y)
        case (.bitwiseAnd, .value(let x), .value(let y)): return try x.opBitwiseAnd(y)
        case (.bitwiseOr, .value(let x), .value(let y)): return try x.opBitwiseOr(y)
        case (.bitwiseXor, .value(let x), .value(let y)): return try x.opBitwiseXor(y)
        case (.intersection, .value(let x), .value(let y)): return try x.opIntersection(y)
        case (.union, .value(let x), .value(let y)): return try x.opUnion(y)
        case (.regex, .value(let x), .value(let y)): return try x.opRegex(y)
        case (.get, .value(let x), .value(let y)): return try x.opGet(y)
        case (.any, .value(let x), .closure(let f)): return try x.opAny(f, variables)
        case (.all, .value(let x), .closure(let f)): return try x.opAll(f, variables)
        case (.and, .value(let x), .value(let y)): return try x.opAnd(y)
        case (.or, .value(let x), .value(let y)): return try x.opOr(y)
        case (.lazyAnd, .value(let x), .closure(let f)): return try x.opLazyAnd(f, variables)
        case (.lazyOr, .value(let x), .closure(let f)): return try x.opLazyOr(f, variables)
        case (.ffi(let name), _, _): throw Biscuit.EvaluationError.unknownForeignFunction(name)
        case (.tryOr, .closure(let f), .value(let y)): return try f.opTryOr(y, variables)
        default: throw Biscuit.EvaluationError.typeError
        }
    }
}
