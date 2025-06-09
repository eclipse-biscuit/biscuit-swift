/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// A resultBuilder used to construct compound statements, such as checks, policies and rules.
    /// It can contain facts and expressions.
    @resultBuilder
    public struct StatementBuilder: Sendable, Hashable {
        let predicates: [Predicate]
        let expressions: [Expression]

        public static func buildBlock(_ builders: StatementBuilder...) -> StatementBuilder {
            StatementBuilder(
                predicates: builders.flatMap { $0.predicates },
                expressions: builders.flatMap { $0.expressions }
            )
        }

        public static func buildOptional(_ builder: StatementBuilder?) -> StatementBuilder {
            builder ?? StatementBuilder(predicates: [], expressions: [])
        }

        public static func buildEither(first: StatementBuilder) -> StatementBuilder {
            first
        }

        public static func buildEither(second: StatementBuilder) -> StatementBuilder {
            second
        }

        public static func buildArray(_ builders: [StatementBuilder]) -> StatementBuilder {
            StatementBuilder(
                predicates: builders.flatMap { $0.predicates },
                expressions: builders.flatMap { $0.expressions }
            )
        }

        public static func buildExpression(_ predicate: Predicate) -> StatementBuilder {
            StatementBuilder(predicates: [predicate], expressions: [])
        }

        public static func buildExpression<E: ExpressionConvertible>(_ expression: E) -> StatementBuilder {
            StatementBuilder(predicates: [], expressions: [expression.expression])
        }
    }
}
