/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
/// A policy, contained in an Authorizer, which determines if biscuit authorization succeeds or
/// fails
public struct Policy: Sendable, Hashable, CustomStringConvertible {
    /// The queries of this Policy. For the check to pass, at least one must be true.
    public let queries: [Biscuit.Query]
    /// The kind of this Policy
    public let kind: Kind

    /// A variety of Policy
    public struct Kind: Sendable, Hashable, CustomStringConvertible {
        enum Wrapped { case allow, deny }
        let wrapped: Wrapped

        /// The kind of an "allow if" Policy
        public static var allowIf: Kind { Kind(wrapped: .allow) }
        /// The kind of an "deny if" Policy
        public static var denyIf: Kind { Kind(wrapped: .deny) }

        public var description: String {
            switch self.wrapped {
                case .allow: "allow if"
                case .deny: "deny if"
            }
        }
    }

    /// Construct a policy by parsing a String of Datalog
    /// - Parameters:
    ///   - datalog: the datalog that will be parsed
    /// - Throws: Throws a `DatalogError` on a parsing error
    public init(_ datalog: String) throws {
        let parser = try Parser.forPolicy(using: datalog)
        self = parser.policies[0]
    }

    /// Construct an "allow if" policy
    ///
    /// - Parameters:
    ///   - trusting: any scopes that will trusted for this policy
    ///   - predicates: the predicates of this policy
    public static func allowIf<each T: TrustedScopeConvertible>(
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) rethrows -> Policy {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try Policy(kind: .allowIf, trusting: scopes, predicates())
    }

    /// Construct a "deny if" policy
    ///
    /// - Parameters:
    ///   - trusting: any scopes that will trusted for this policy
    ///   - predicates: the predicates of this policy
    public static func denyIf<each T: TrustedScopeConvertible>(
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) rethrows -> Policy {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try Policy(kind: .denyIf, trusting: scopes, predicates())
    }

    init(kind: Kind, trusting: [TrustedScope] = [], _ predicates: Biscuit.StatementBuilder) {
        self.kind = kind
        self.queries = [Biscuit.Query(predicates.predicates, predicates.expressions, trusting)]
    }


    init(_ rules: [Biscuit.Query], _ kind: Kind) {
        self.queries = rules
        self.kind = kind
    }

    /// A policy which always succeeds
    public static var alwaysAllow: Policy { Policy.allowIf { true } }

    public var description: String {
        return "\(kind) \(queries.map { $0.description }.joined(separator: ", "))"
    }
}
