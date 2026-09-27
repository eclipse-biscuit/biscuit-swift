/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
struct Resolution {
    var stable = Facts()
    var recent = Facts()
    var new = Facts()
    var publicKeys: [Biscuit.ThirdPartyKey: Scope] = [:]

    typealias Scope = Set<Int>

    init(biscuit: Biscuit, authorizer: Biscuit.Authorizer) throws {
        var factCount = 0
        let authority = biscuit.authority
        factCount += try authority.addFacts(to: &self, in: 0)
        for (index, block) in biscuit.attenuations.enumerated() {
            let blockID = index + 1
            factCount += try block.addFacts(to: &self, in: blockID)
            if let signature = block.externalSignature {
                self.publicKeys[signature.publicKey, default: []].insert(blockID)
            }
        }
        factCount += try authorizer.addFacts(to: &self)

        var iterationCount = 0
        while !self.recent.isEmpty {
            try self.applyRules(authority.datalog.rules, authority.datalog.trusted, 0)
            for (index, block) in biscuit.attenuations.enumerated() {
                try self.applyRules(
                    block.datalog.rules,
                    block.datalog.trusted,
                    index + 1
                )
            }
            try self.applyRules(authorizer.rules, [], nil)
            self.stable.formUnion(self.recent)
            self.recent = self.new
            self.new = Facts()
            factCount += self.recent.count
            iterationCount += 1
            guard authorizer.limits.maximumFacts.map({ $0 >= factCount }) ?? true else {
                throw Biscuit.EvaluationError.tooManyFacts
            }
            guard authorizer.limits.maximumIterations.map({ $0 >= iterationCount }) ?? true else {
                throw Biscuit.EvaluationError.tooManyIterations
            }
        }
    }

    mutating func applyRules(_ rules: [Rule], _ trusted: [TrustedScope], _ blockID: Int?) throws {
        let trusted = self.trustScopes(trusted, blockID)
        for rule in rules {
            let trusted = rule.trusted.isEmpty ? trusted : self.trustScopes(rule.trusted, blockID)
            try self.applyRule(rule, blockID, trusted)
        }
    }

    mutating func applyRule(_ rule: Rule, _ blockID: Int?, _ trusted: Scope) throws {
        let origin = Match(blockID.map { Scope([$0]) } ?? [])
        for predicate in rule.bodyPredicates {
            for match in self.recent.matches(predicate, trusted, origin) {
                let predicates = rule.bodyPredicates.filter { $0 != predicate }
                for match in self.collectAllVariables(predicates[...], trusted, match) {
                    if try rule.expressions.allSatisfy({ expr in try expr.evaluate(match.variables) }) {
                        let fact = try rule.head.makeConcrete(variables: match.variables)
                        self.addFact(fact, match.scope)
                    }
                }
            }
        }
    }

    func checkQueryIf(_ query: Biscuit.Query, _ trusted: Scope) throws -> Bool {
        var success = false
        for match in self.collectStableVariables(query.predicates[...], trusted, Match()) {
            success = try query.expressions.allSatisfy({ try $0.evaluate(match.variables) })
            if success { break }
        }
        return success
    }

    func checkQueryAll(_ query: Biscuit.Query, _ trusted: Scope) throws -> Bool {
        var success = false
        for match in self.collectStableVariables(query.predicates[...], trusted, Match()) {
            success = try query.expressions.allSatisfy({ try $0.evaluate(match.variables) })
            guard success else { break }
        }
        return success
    }

    func collectStableVariables(
        _ predicates: ArraySlice<Predicate>,
        _ trusted: Scope,
        _ match: Match
    ) -> [Match] {
        guard !predicates.isEmpty else { return [match] }
        let start = predicates.startIndex
        return self.stable.matches(predicates[start], trusted, match).flatMap {
            self.collectStableVariables(predicates[(start + 1)...], trusted, $0)
        }
    }

    func collectAllVariables(
        _ predicates: ArraySlice<Predicate>,
        _ trusted: Scope,
        _ match: Match
    ) -> [Match] {
        guard !predicates.isEmpty else { return [match] }
        let start = predicates.startIndex
        return self.allFactsThatSupport(predicates[start], trusted, match).flatMap {
            self.collectAllVariables(predicates[(start + 1)...], trusted, $0)
        }
    }

    func allFactsThatSupport(
        _ predicate: Predicate,
        _ trusted: Scope,
        _ match: Match = Match()
    )
        -> [Match]
    {
        var matches = self.stable.matches(predicate, trusted, match)
        matches.append(contentsOf: self.recent.matches(predicate, trusted, match))
        return matches
    }

    func trustScopes(_ scopes: [TrustedScope], _ blockID: Int?) -> Scope {
        var trusted: Scope = []
        if scopes.isEmpty {
            trusted.insert(0)
        }
        if let blockID = blockID {
            trusted.insert(blockID)
        }
        for scope in scopes {
            switch scope.wrapped {
            case .authority:
                trusted.insert(0)
            case .previous:
                if let blockID = blockID {
                    for id in 0..<blockID {
                        trusted.insert(id)
                    }
                }
            case .publicKey(let publicKey):
                if let blockIDs = self.publicKeys[publicKey] {
                    trusted.formUnion(blockIDs)
                }
            }
        }
        return trusted
    }

    mutating func addFact(_ fact: Fact, _ scope: Scope) {
        guard !self.stable.contains(fact, scope) && !self.recent.contains(fact, scope) else {
            return
        }
        self.new.insert(fact, scope)
    }

    struct Facts {
        struct FactId: Hashable {
            var name: String
            var termCount: Int

            init(_ predicate: Predicate) {
                self.name = predicate.name
                self.termCount = predicate.terms.count
            }

            init(_ fact: Fact) {
                self.name = fact.name
                self.termCount = fact.values.count
            }
        }

        var facts: [FactId: [Scope: Set<Fact>]] = [:]

        var isEmpty: Bool { self.facts.isEmpty }

        var count: Int {
            self.facts.values.reduce(0) { count, scopes in
                scopes.values.reduce(count) { $0 + $1.count }
            }
        }

        func contains(_ fact: Fact, _ scope: Scope) -> Bool {
            self.facts[FactId(fact)]?[scope]?.contains(fact) == true
        }

        mutating func insert(_ fact: Fact, _ scope: Scope) {
            self.facts[FactId(fact), default: [:]][scope, default: []].insert(fact)
        }

        mutating func formUnion(_ other: Facts) {
            for (id, scopes) in other.facts {
                for (scope, facts) in scopes {
                    self.facts[id, default: [:]][scope, default: []].formUnion(facts)
                }
            }
        }

        func matches(_ predicate: Predicate, _ trusted: Scope, _ match: Match) -> [Match] {
            var matches: [Match] = []
            for (scope, facts) in self.facts[FactId(predicate)] ?? [:]
            where scope.isSubset(of: trusted) {
                for fact in facts {
                    if let variables = fact.supportsWithVariables(predicate, match.variables) {
                        matches.append(Match(match.scope.union(scope), variables))
                    }
                }
            }
            return matches
        }
    }

    struct Match {
        var scope: Scope
        var variables: [String: Value]

        init(_ scope: Scope = [], _ variables: [String: Value] = [:]) {
            self.scope = scope
            self.variables = variables
        }
    }
}

extension Biscuit.Block {
    fileprivate func addFacts(to facts: inout Resolution, in blockID: Int) throws -> Int {
        let revocationID = Fact(index: blockID, revocationID: self.signature)
        facts.recent.insert(revocationID, [])
        for fact in self.datalog.facts {
            facts.recent.insert(fact, [blockID])
        }
        return 1 + self.datalog.facts.count
    }
}

extension Biscuit.Authorizer {
    fileprivate func addFacts(to facts: inout Resolution) throws -> Int {
        for fact in self.facts {
            facts.recent.insert(fact, [])
        }
        return self.facts.count
    }
}
