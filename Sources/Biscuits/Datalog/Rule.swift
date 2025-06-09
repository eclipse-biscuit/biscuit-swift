/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
/// A rule which can be used to generate facts by implication
public struct Rule: Sendable, Hashable, CustomStringConvertible {
    /// The head predicate of the rule
    public var head: Predicate
    /// The predicates in the body of the rule
    public var bodyPredicates: [Predicate]
    /// Expressions in the body of the rule
    public var expressions: [Expression]
    /// Trusted scopes for the rule
    public var trusted: [TrustedScope]

    /// Construct a rule
    ///
    /// - Parameters:
    ///   - head: the fact that will be implied by this rule
    ///   - trusting: any scopes that will trusted for this rule
    ///   - predicates: the predicates of this rule
    /// - Throws: Throws a `ValidationError` if the head contains a variable which is not used in
    ///   the predicates of the body
    public init<each T: TrustedScopeConvertible>(
        head: Predicate,
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) throws {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        let predicates = try predicates()
        if !head.terms.allSatisfy({ term in
            term.isConcrete || predicates.predicates.contains(where: { $0.terms.contains(term) })
        }) {
            throw Biscuit.ValidationError.unboundVariableInHead
        }
        self.head = head
        self.bodyPredicates = predicates.predicates
        self.expressions = predicates.expressions
        self.trusted = scopes
    }

    /// Construct a rule by parsing a String of Datalog
    /// - Parameters:
    ///   - datalog: the datalog that will be parsed
    /// - Throws: Throws a `DatalogError` on a parsing error
    public init(_ datalog: String) throws {
        let parser = try Parser.forRule(using: datalog)
        self = parser.rules[0]
    }

    init(proto: Biscuit_Format_Schema_RuleV2, interner: BlockInternmentTable) throws {
        guard proto.hasHead else {
            throw Biscuit.ValidationError.missingRuleHead
        }
        self.head = try Predicate(proto: proto.head, interner: interner)
        self.bodyPredicates = try proto.body.map { try Predicate(proto: $0, interner: interner) }
        self.expressions = try proto.expressions.map { try Expression(proto: $0, interner: interner) }
        self.trusted = try proto.scope.map { try TrustedScope(proto: $0, interner: interner) }
        if !self.head.terms.allSatisfy({term in
            term.isConcrete || self.bodyPredicates.contains(where: { $0.terms.contains(term) })
        }) {
            throw Biscuit.ValidationError.unboundVariableInHead
        }
    }

    init(_ head: Predicate, _ body: [Predicate], _ expressions: [Expression], _ trusted: [TrustedScope]) {
        self.head = head 
        self.bodyPredicates = body
        self.expressions = expressions
        self.trusted = trusted
    }

    func intern(
        _ interner: inout BlockInternmentTable,
        _ symbols: inout [String],
        _ publicKeys: inout [Biscuit.ThirdPartyKey]
    ) {
        self.head.intern(&interner, &symbols)
        for fact in self.bodyPredicates {
            fact.intern(&interner, &symbols)
        }
        for expression in self.expressions {
            expression.intern(&interner, &symbols)
        }
        for scope in self.trusted {
            scope.intern(&interner, &publicKeys)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_RuleV2 {
        var proto = Biscuit_Format_Schema_RuleV2()
        proto.head = self.head.proto(interner)
        proto.body = self.bodyPredicates.map { $0.proto(interner) }
        proto.expressions = self.expressions.map { $0.proto(interner) }
        proto.scope = self.trusted.map { $0.proto(interner) }
        return proto
    }

    public var description: String {
        let predicates = [bodyPredicates.map { "\($0)" }, expressions.map { "\($0)" }].joined()
            .joined(separator: ", ")
        if trusted.isEmpty {
            return "\(head) <- \(predicates)"
        } else {
            let scopes = trusted.map { "\($0)" }.joined(separator: ", ")
            return "\(head) <- \(predicates) trusting \(scopes)"
        }
    }
}
