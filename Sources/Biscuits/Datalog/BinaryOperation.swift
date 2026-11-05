/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// A binary operation which can appear in a Datalog expression
    public struct BinaryOperation: Sendable, Hashable, CustomStringConvertible {
        internal enum Wrapped: Hashable {
            case greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual
            case strictEqual, strictNotEqual, equal, notEqual
            case and, or, lazyAnd, lazyOr
            case add, subtract, multiply, divide
            case bitwiseAnd, bitwiseOr, bitwiseXor
            case contains, startsWith, endsWith, matches, intersection, union
            case any, all, get, tryOr
            case extern
        }

        internal let wrapped: Wrapped

        init(_ wrapped: Wrapped) {
            self.wrapped = wrapped
        }

        init(kind: Biscuit_Format_Schema_OpBinary.Kind) {
            self =
                switch kind {
                case .greaterThan: .greaterThan
                case .greaterOrEqual: .greaterThanOrEqual
                case .lessThan: .lessThan
                case .lessOrEqual: .lessThanOrEqual
                case .equal: .strictEqual
                case .notEqual: .strictNotEqual
                case .heterogeneousEqual: .equal
                case .heterogeneousNotEqual: .notEqual
                case .and: .and
                case .or: .or
                case .lazyAnd: .lazyAnd
                case .lazyOr: .lazyOr
                case .add: .add
                case .sub: .subtract
                case .mul: .multiply
                case .div: .divide
                case .bitwiseAnd: .bitwiseAnd
                case .bitwiseOr: .bitwiseOr
                case .bitwiseXor: .bitwiseXor
                case .contains: .contains
                case .prefix: .startsWith
                case .suffix: .endsWith
                case .regex: .matches
                case .intersection: .intersection
                case .union: .union
                case .any: .any
                case .all: .all
                case .get: .get
                case .tryOr: .tryOr
                case .ffi: .extern
                }
        }

        /// The `>` operation
        public static var greaterThan: Self { Self(.greaterThan) }
        /// The `>=` operation
        public static var greaterThanOrEqual: Self { Self(.greaterThanOrEqual) }
        /// The `<` operation
        public static var lessThan: Self { Self(.lessThan) }
        /// The `<=` operation
        public static var lessThanOrEqual: Self { Self(.lessThanOrEqual) }
        /// The `===` operation, which requires both operands to have the same type
        public static var strictEqual: Self { Self(.strictEqual) }
        /// The `!==` operation, which requires both operands to have the same type
        public static var strictNotEqual: Self { Self(.strictNotEqual) }
        /// The `==` operation, which allows operands of different types
        public static var equal: Self { Self(.equal) }
        /// The `!=` operation, which allows operands of different types
        public static var notEqual: Self { Self(.notEqual) }
        /// The `&&` operation, evaluating both operands
        public static var and: Self { Self(.and) }
        /// The `||` operation, evaluating both operands
        public static var or: Self { Self(.or) }
        /// The `&&` operation, only evaluating the right operand if needed
        public static var lazyAnd: Self { Self(.lazyAnd) }
        /// The `||` operation, only evaluating the right operand if needed
        public static var lazyOr: Self { Self(.lazyOr) }
        /// The `+` operation
        public static var add: Self { Self(.add) }
        /// The `-` operation
        public static var subtract: Self { Self(.subtract) }
        /// The `*` operation
        public static var multiply: Self { Self(.multiply) }
        /// The `/` operation
        public static var divide: Self { Self(.divide) }
        /// The `&` operation
        public static var bitwiseAnd: Self { Self(.bitwiseAnd) }
        /// The `|` operation
        public static var bitwiseOr: Self { Self(.bitwiseOr) }
        /// The `^` operation
        public static var bitwiseXor: Self { Self(.bitwiseXor) }
        /// The `.contains()` operation
        public static var contains: Self { Self(.contains) }
        /// The `.starts_with()` operation
        public static var startsWith: Self { Self(.startsWith) }
        /// The `.ends_with()` operation
        public static var endsWith: Self { Self(.endsWith) }
        /// The `.matches()` operation
        public static var matches: Self { Self(.matches) }
        /// The `.intersection()` operation
        public static var intersection: Self { Self(.intersection) }
        /// The `.union()` operation
        public static var union: Self { Self(.union) }
        /// The `.any()` operation
        public static var any: Self { Self(.any) }
        /// The `.all()` operation
        public static var all: Self { Self(.all) }
        /// The `.get()` operation
        public static var get: Self { Self(.get) }
        /// The `.try_or()` operation
        public static var tryOr: Self { Self(.tryOr) }
        /// A call to any foreign function with one argument, `.extern::name()`
        public static var extern: Self { Self(.extern) }

        public var description: String {
            switch self.wrapped {
            case .greaterThan: ">"
            case .greaterThanOrEqual: ">="
            case .lessThan: "<"
            case .lessThanOrEqual: "<="
            case .strictEqual: "==="
            case .strictNotEqual: "!=="
            case .equal: "=="
            case .notEqual: "!="
            case .and, .lazyAnd: "&&"
            case .or, .lazyOr: "||"
            case .add: "+"
            case .subtract: "-"
            case .multiply: "*"
            case .divide: "/"
            case .bitwiseAnd: "&"
            case .bitwiseOr: "|"
            case .bitwiseXor: "^"
            case .contains: ".contains()"
            case .startsWith: ".starts_with()"
            case .endsWith: ".ends_with()"
            case .matches: ".matches()"
            case .intersection: ".intersection()"
            case .union: ".union()"
            case .any: ".any()"
            case .all: ".all()"
            case .get: ".get()"
            case .tryOr: ".try_or()"
            case .extern: ".extern::()"
            }
        }
    }
}
