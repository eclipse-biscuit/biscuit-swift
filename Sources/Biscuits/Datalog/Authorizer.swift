/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    func validateChecks(_ resolution: Resolution) throws {
        try self.authority.validateChecks(resolution, .block(0))
        for (index, block) in self.attenuations.enumerated() {
            try block.validateChecks(resolution, .block(index + 1))
        }
    }
}

extension Biscuit.Block {
    func validateChecks(_ resolution: Resolution, _ scope: Resolution.Scope) throws {
        let trusted = resolution.trustScopes(self.datalog.trusted, scope.blockID)
        for check in self.datalog.checks {
            guard try check.validate(resolution, trusted, scope) else {
                throw Biscuit.AuthorizationError(check: check)
            }
        }
    }
}

extension Biscuit {
    /// An Authorizer can be used to authorize a Biscuit.
    @resultBuilder
    public struct Authorizer: Sendable, Hashable, CustomStringConvertible {
        /// The policies contained in this Authorizer
        public var policies: [Policy] = []
        /// The checks contained in this Authorizer
        public var checks: [Check] = []
        /// The facts contained in this Authorizer
        public var facts: [Fact] = []
        /// The rules contained in this Authorizer
        public var rules: [Rule] = []
        /// The scopes trusted during execution of this Authorizer
        public var scope: [TrustedScope] = []
        /// The limits on execution of this Authorizer
        public var limits: Limits = Limits.noLimits

        /// Limits on the execution time of the authorizer
        public struct Limits: Sendable, Hashable {
            /// The maximum number of facts to be generated during authorization
            public var maximumFacts: Int? = nil
            /// The maximum number of iterations to perform during authorization
            public var maximumIterations: Int? = nil
            /// Allow authorization without limiting execution time
            public static var noLimits: Limits { Limits() }
        }

        init() {}

        init(limits: Limits) {
            self = Authorizer()
            self.limits = limits
        }

        /// Construct an Authorizer
        ///
        /// - Parameter limitedBy: limits on the execution time of this Authorizer
        /// - Parameter datalog: the Datalog contents of this Authorizer
        public init(limitedBy: Limits = Limits.noLimits, @Authorizer _ datalog: () throws -> Authorizer) rethrows {
            self = try datalog()
            self.limits = limitedBy
        }

        /// Construct an Authorizer from a String of Datalog
        ///
        /// - Parameter datalog: the Datalog contents of this Authorizer as a String
        /// - Parameter limitedBy: limits on the execution time of this Authorizer
        public init(_ datalog: String, limitedBy: Limits = Limits.noLimits) throws {
            self.limits = limitedBy
            let parser = try Parser.forAuthorizer(using: datalog)
            self.policies = parser.policies
            self.checks = parser.checks
            self.facts = parser.facts
            self.rules = parser.rules
            self.scope = parser.origins
            guard self.policies.count > 0 else {
                throw Biscuit.EvaluationError.authorizerWithoutPolicy
            }
        }

        public static func buildBlock(_ authorizer: Authorizer...) -> Authorizer {
            var auth = Authorizer()
            auth.policies = authorizer.flatMap { $0.policies }
            auth.checks = authorizer.flatMap { $0.checks }
            auth.facts = authorizer.flatMap { $0.facts }
            auth.rules = authorizer.flatMap { $0.rules }
            auth.scope = authorizer.flatMap { $0.scope }
            return auth
        }

        public static func buildOptional(_ authorizer: Authorizer?) -> Authorizer {
            authorizer ?? Authorizer()
        }

        public static func buildEither(first: Authorizer) -> Authorizer {
            first
        }

        public static func buildEither(second: Authorizer) -> Authorizer {
            second
        }

        public static func buildArray(_ authorizers: [Authorizer]) -> Authorizer {
            var auth = Authorizer()
            auth.policies = authorizers.flatMap { $0.policies }
            auth.checks = authorizers.flatMap { $0.checks }
            auth.facts = authorizers.flatMap { $0.facts }
            auth.rules = authorizers.flatMap { $0.rules }
            auth.scope = authorizers.flatMap { $0.scope }
            return auth
        }

        public static func buildExpression(_ fact: Fact) -> Authorizer {
            var auth = Authorizer()
            auth.facts = [fact]
            return auth
        }

        public static func buildExpression(_ rule: Rule) -> Authorizer {
            var auth = Authorizer()
            auth.rules = [rule]
            return auth
        }

        public static func buildExpression(_ check: Check) -> Authorizer {
            var auth = Authorizer()
            auth.checks = [check]
            return auth
        }

        public static func buildExpression(_ policy: Policy) -> Authorizer {
            var auth = Authorizer()
            auth.policies = [policy]
            return auth
        }

        public static func buildExpression(_ trusting: Trusting) -> Authorizer {
            var auth = Authorizer()
            auth.scope = trusting.trusted
            return auth
        }

        func validateChecksAndPolicies(_ resolution: Resolution) throws -> Biscuit.Authorization {
            for check in self.checks {
                guard try check.validate(resolution, [0], .authorizer) else {
                    throw Biscuit.AuthorizationError(check: check)
                }
            }
            for policy in self.policies {
                if let authorization = try policy.validate(resolution) {
                    return authorization
                }
            }
            throw Biscuit.AuthorizationError()
        }

        public var description: String {
            let trusting = "trusting \(self.scope.map { $0.description }.joined(separator: " "));"
            let facts = self.facts.map { "\($0);" }.joined(separator: "\n")
            let rules = self.rules.map { "\($0);" }.joined(separator: "\n")
            let checks = self.checks.map { "\($0);" }.joined(separator: "\n")
            let policies = self.policies.map { "\($0);" }.joined(separator: "\n")
            return [trusting, facts, rules, checks, policies].joined(separator: "\n")
        }
    }
}

extension Check {
    func validate(_ resolution: Resolution, _ trusted: Set<Int>, _ scope: Resolution.Scope) throws -> Bool {
        for query in self.queries {
            let trusted =
                if query.trusted.isEmpty {
                    trusted
                } else {
                    resolution.trustScopes(query.trusted, scope.blockID)
                }
            let checkSucceeded =
                switch self.kind.wrapped {
                case .one:
                    try resolution.checkQueryIf(query, trusted)
                case .all:
                    try resolution.checkQueryAll(query, trusted)
                case .reject:
                    try !resolution.checkQueryIf(query, trusted)
                }
            if checkSucceeded {
                return true
            }
        }
        return false
    }
}

extension Policy {
    func validate(_ resolution: Resolution) throws -> Biscuit.Authorization? {
        for query in self.queries {
            let trusted = resolution.trustScopes(query.trusted, nil)
            if try resolution.checkQueryIf(query, trusted) {
                switch self.kind.wrapped {
                case .allow:
                    return Biscuit.Authorization(policy: self)
                case .deny:
                    throw Biscuit.AuthorizationError(deny: self)
                }
            }
        }
        return nil
    }
}
