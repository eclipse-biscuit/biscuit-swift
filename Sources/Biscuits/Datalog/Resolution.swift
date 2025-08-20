/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
struct Resolution {
    var stable: [FactId: Set<Fact>] = [:]
    var recent: [FactId: Set<Fact>] = [:]
    var new: [FactId: Set<Fact>] = [:]
    var publicKeys: [Biscuit.ThirdPartyKey: Set<Int>] = [:]

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
            try self.applyRules(authority.datalog.rules, authority.datalog.trusted, .block(0))
            for (index, block) in biscuit.attenuations.enumerated() {
                try self.applyRules(
                    block.datalog.rules,
                    block.datalog.trusted,
                    .block(index + 1)
                )
            }
            try self.applyRules(authorizer.rules, [], .authorizer)
            for (id, recent) in self.recent {
                self.stable[id, default: []].formUnion(recent)
            }
            self.recent = self.new
            self.new = [:]
            factCount += self.recent.map { $1.count }.reduce(0, +)
            iterationCount += 1
            guard authorizer.limits.maximumFacts.map({ $0 >= factCount }) ?? true else {
                throw Biscuit.EvaluationError.tooManyFacts
            }
            guard authorizer.limits.maximumIterations.map({ $0 >= iterationCount }) ?? true else {
                throw Biscuit.EvaluationError.tooManyIterations
            }
        }
    }

    mutating func applyRules(_ rules: [Rule], _ trusted: [TrustedScope], _ scope: Scope) throws {
        let trusted = self.trustScopes(trusted, scope.blockID)
        for rule in rules {
            let trusted = rule.trusted.isEmpty ? trusted : self.trustScopes(rule.trusted, scope.blockID)
            try self.applyRule(rule, scope, trusted)
        }
    }

    mutating func applyRule(_ rule: Rule, _ scope: Scope, _ trusted: Set<Int>) throws {
        for predicate in rule.bodyPredicates {
            for variables in self.recentFactsThatSupport(predicate, trusted) {
                let predicates = rule.bodyPredicates.filter { $0 != predicate }
                for variables in self.collectAllVariables(predicates[...], trusted, variables) {
                    if try rule.expressions.allSatisfy({ expr in try expr.evaluate(variables) }) {
                        try self.addFact(rule.head.makeConcrete(variables: variables), scope)
                    }
                }
            }
        }
    }

    func checkQueryIf(_ query: Biscuit.Query, _ trusted: Set<Int>) throws -> Bool {
        var success = false
        for variables in self.collectStableVariables(query.predicates[...], trusted, [:]) {
            success = try query.expressions.allSatisfy({ try $0.evaluate(variables) })
            if success { break }
        }
        return success
    }

    func checkQueryAll(_ query: Biscuit.Query, _ trusted: Set<Int>) throws -> Bool {
        var success = false
        for variables in self.collectStableVariables(query.predicates[...], trusted, [:]) {
            success = try query.expressions.allSatisfy({ try $0.evaluate(variables) })
            guard success else { break }
        }
        return success
    }

    func collectStableVariables(
        _ predicates: ArraySlice<Predicate>,
        _ trusted: Set<Int>,
        _ variables: [String: Value]
    ) -> [[String: Value]] {
        guard !predicates.isEmpty else { return [variables] }
        let start = predicates.startIndex
        return self.stableFactsThatSupport(predicates[start], trusted, variables).flatMap {
            self.collectStableVariables(predicates[(start + 1)...], trusted, $0)
        }
    }

    func collectAllVariables(
        _ predicates: ArraySlice<Predicate>,
        _ trusted: Set<Int>,
        _ variables: [String: Value]
    ) -> [[String: Value]] {
        guard !predicates.isEmpty else { return [variables] }
        let start = predicates.startIndex
        return self.allFactsThatSupport(predicates[start], trusted, variables).flatMap {
            self.collectAllVariables(predicates[(start + 1)...], trusted, $0)
        }
    }

    func recentFactsThatSupport(
        _ predicate: Predicate,
        _ trusted: Set<Int>,
        _ vars: [String: Value] = [:]
    )
        -> [[String: Value]]
    {
        var relevantFacts: Set<Fact> = self.recent[FactId(predicate, .authorizer)] ?? []
        for blockID in trusted {
            relevantFacts.formUnion(self.recent[FactId(predicate, .block(blockID))] ?? [])
        }
        return relevantFacts.compactMap { $0.supportsWithVariables(predicate, vars) }
    }

    func stableFactsThatSupport(
        _ predicate: Predicate,
        _ trusted: Set<Int>,
        _ vars: [String: Value] = [:]
    )
        -> [[String: Value]]
    {
        var relevantFacts: Set<Fact> = self.stable[FactId(predicate, .authorizer)] ?? []
        for blockID in trusted {
            relevantFacts.formUnion(self.stable[FactId(predicate, .block(blockID))] ?? [])
        }
        return relevantFacts.compactMap { $0.supportsWithVariables(predicate, vars) }
    }

    func allFactsThatSupport(
        _ predicate: Predicate,
        _ trusted: Set<Int>,
        _ vars: [String: Value] = [:]
    )
        -> [[String: Value]]
    {
        var facts = self.stableFactsThatSupport(predicate, trusted, vars)
        facts.append(contentsOf: self.recentFactsThatSupport(predicate, trusted, vars))
        return facts
    }

    func trustScopes(_ scopes: [TrustedScope], _ blockID: Int?) -> Set<Int> {
        var trusted: Set<Int> = []
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
        let factID = FactId(fact, scope)
        guard
            self.stable[factID]?.contains(fact) != true
                && self.recent[factID]?.contains(fact) != true
        else { return }
        self.new[factID, default: []].insert(fact)
    }

    enum Scope: Hashable {
        case block(Int)
        case authorizer

        var blockID: Int? {
            switch self {
            case .block(let blockID): blockID
            case .authorizer: nil
            }
        }
    }

    struct FactId: Hashable {
        var name: String
        var termCount: Int
        var scope: Scope

        init(_ predicate: Predicate, _ scope: Scope) {
            self.init(predicate.name, predicate.terms.count, scope)
        }

        init(_ fact: Fact, _ scope: Scope) {
            self.init(fact.name, fact.values.count, scope)
        }

        init(_ name: String, _ termCount: Int, _ scope: Scope) {
            self.name = name
            self.termCount = termCount
            self.scope = scope
        }
    }
}

extension Biscuit.Block {
    fileprivate func addFacts(to facts: inout Resolution, in blockID: Int) throws -> Int {
        let revocationID = Fact(index: blockID, revocationID: self.signature)
        facts.recent[Resolution.FactId(revocationID, .authorizer), default: []].insert(revocationID)
        for fact in self.datalog.facts {
            facts.recent[Resolution.FactId(fact, .block(blockID)), default: []].insert(fact)
        }
        return 1 + self.datalog.facts.count
    }
}

extension Biscuit.Authorizer {
    fileprivate func addFacts(to facts: inout Resolution) throws -> Int {
        for fact in self.facts {
            facts.recent[Resolution.FactId(fact, .authorizer), default: []].insert(fact)
        }
        return self.facts.count
    }
}
