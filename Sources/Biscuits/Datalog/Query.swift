/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// A query about a Biscuit that can be true or false.
    public struct Query: Sendable, Hashable, CustomStringConvertible {
        /// The predicates of this query.
        public let predicates: [Predicate]
        /// The expressions of this query.
        public let expressions: [Expression]
        /// The trusted scopes of this query
        public let trusted: [TrustedScope]

        init(proto: Biscuit_Format_Schema_Rule, interner: BlockInternmentTable) throws {
            guard proto.head == Predicate.query else {
                throw ValidationError.invalidQueryHead
            }
            self.predicates = try proto.body.map { try Predicate(proto: $0, interner: interner) }
            self.expressions = try proto.expressions.map { try Expression(proto: $0, interner: interner) }
            self.trusted = try proto.scope.map { try TrustedScope(proto: $0, interner: interner) }
        }

        init(_ predicates: [Predicate], _ expressions: [Expression], _ trusted: [TrustedScope]) {
            self.predicates = predicates
            self.expressions = expressions
            self.trusted = trusted
        }

        func intern(
            _ interner: inout BlockInternmentTable,
            _ symbols: inout [String],
            _ publicKeys: inout [Biscuit.ThirdPartyKey]
        ) {
            for fact in self.predicates {
                fact.intern(&interner, &symbols)
            }
            for expression in self.expressions {
                expression.intern(&interner, &symbols)
            }
            for scope in self.trusted {
                scope.intern(&interner, &publicKeys)
            }
        }

        func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Rule {
            var proto = Biscuit_Format_Schema_Rule()
            proto.head = Predicate.query
            proto.body = self.predicates.map { $0.proto(interner) }
            proto.expressions = self.expressions.map { $0.proto(interner) }
            proto.scope = self.trusted.map { $0.proto(interner) }
            return proto
        }

        public var description: String {
            let predicates = [predicates.map { "\($0)" }, expressions.map { "\($0)" }].joined()
                .joined(separator: ", ")
            if trusted.isEmpty {
                return predicates
            } else {
                let scopes = trusted.map { "\($0)" }.joined(separator: ", ")
                return "\(predicates) trusting \(scopes)"
            }
        }
    }
}
