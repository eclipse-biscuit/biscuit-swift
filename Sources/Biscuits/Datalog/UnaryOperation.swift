/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// A unary operation which can appear in a Datalog expression
    public struct UnaryOperation: Sendable, Hashable, CustomStringConvertible {
        internal enum Wrapped: Hashable {
            case negate, parens, length, type, extern
        }

        internal let wrapped: Wrapped

        init(_ wrapped: Wrapped) {
            self.wrapped = wrapped
        }

        init(kind: Biscuit_Format_Schema_OpUnary.Kind) {
            self =
                switch kind {
                case .negate: .negate
                case .parens: .parens
                case .length: .length
                case .typeOf: .type
                case .ffi: .extern
                }
        }

        /// The `!` operation
        public static var negate: Self { Self(.negate) }
        /// Parentheses grouping an expression, `()`
        public static var parens: Self { Self(.parens) }
        /// The `.length()` operation
        public static var length: Self { Self(.length) }
        /// The `.type()` operation
        public static var type: Self { Self(.type) }
        /// A call to any foreign function with no arguments, `.extern::name()`
        public static var extern: Self { Self(.extern) }

        public var description: String {
            switch self.wrapped {
            case .negate: "!"
            case .parens: "()"
            case .length: ".length()"
            case .type: ".type()"
            case .extern: ".extern::()"
            }
        }
    }
}
