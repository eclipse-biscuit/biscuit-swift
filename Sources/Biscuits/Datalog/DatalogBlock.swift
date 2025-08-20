/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension Biscuit {
    /// A block of Datalog that can be included as part of a Biscuit
    @resultBuilder
    public struct DatalogBlock: Sendable, Hashable, CustomStringConvertible {
        var version: UInt32
        var symbols: [String]
        var publicKeys: [Biscuit.ThirdPartyKey]
        /// The context string of this block, if one was specified
        public var context: String?
        /// The checks contained in this block
        public var checks: [Check]
        /// The facts contained in this block
        public var facts: [Fact]
        /// The rules contained in this block
        public var rules: [Rule]
        /// The scopes trusted for checks and rules in this block
        public var trusted: [TrustedScope]

        init(
            checks: [Check] = [],
            facts: [Fact] = [],
            rules: [Rule] = [],
            trusted: [TrustedScope] = [],
            context: String? = nil
        ) {
            self.version = 6
            self.symbols = []
            self.publicKeys = []
            self.context = context
            self.checks = checks
            self.facts = facts
            self.rules = rules
            self.trusted = trusted
        }

        /// Construct a DatalogBlock
        ///
        /// - Parameter context: the context that will be included with this DatalogBlock
        /// - Parameter datalog: the Datalog contents of this DatalogBlock
        public init(context: String? = nil, @DatalogBlock _ datalog: () throws -> DatalogBlock) rethrows {
            self = try datalog()
            self.context = context
        }

        /// Construct a DatalogBlock from a String of Datalog
        ///
        /// - Parameter datalog: the Datalog contents of this DatalogBlock as a String
        public init(_ datalog: String, context: String? = nil) throws {
            let parser = try Parser.forDatalogBlock(using: datalog)
            self.version = 6
            self.symbols = parser.symbols
            self.publicKeys = parser.publicKeys
            self.checks = parser.checks
            self.facts = parser.facts
            self.rules = parser.rules
            self.trusted = parser.origins
            self.context = context
        }

        public static func buildBlock(_ block: DatalogBlock...) -> DatalogBlock {
            DatalogBlock(
                checks: block.flatMap { $0.checks },
                facts: block.flatMap { $0.facts },
                rules: block.flatMap { $0.rules },
                trusted: block.flatMap { $0.trusted },
                context: block.compactMap { $0.context }.joined()
            )
        }

        public static func buildOptional(_ block: DatalogBlock?) -> DatalogBlock {
            block ?? DatalogBlock()
        }

        public static func buildEither(first: DatalogBlock) -> DatalogBlock {
            first
        }

        public static func buildEither(second: DatalogBlock) -> DatalogBlock {
            second
        }

        public static func buildArray(_ blocks: [DatalogBlock]) -> DatalogBlock {
            DatalogBlock(
                checks: blocks.flatMap { $0.checks },
                facts: blocks.flatMap { $0.facts },
                rules: blocks.flatMap { $0.rules },
                trusted: blocks.flatMap { $0.trusted },
                context: blocks.compactMap { $0.context }.joined()
            )
        }

        public static func buildExpression(_ fact: Fact) -> DatalogBlock {
            DatalogBlock(facts: [fact])
        }

        public static func buildExpression(_ rule: Rule) -> DatalogBlock {
            DatalogBlock(rules: [rule])
        }

        public static func buildExpression(_ check: Check) -> DatalogBlock {
            DatalogBlock(checks: [check])
        }

        public static func buildExpression(_ trusting: Trusting) -> DatalogBlock {
            DatalogBlock(trusted: trusting.trusted)
        }

        public var description: String {
            let trusting = "trusting \(self.trusted.map { $0.description }.joined(separator: " "));"
            let facts = self.facts.map { "\($0);" }.joined(separator: "\n")
            let rules = self.rules.map { "\($0);" }.joined(separator: "\n")
            let checks = self.checks.map { "\($0);" }.joined(separator: "\n")
            return [trusting, facts, rules, checks].joined(separator: "\n")
        }

        mutating func attachToBiscuit(interner: inout BlockInternmentTable, context: String?) {
            for trusted in self.trusted {
                trusted.intern(&interner, &self.publicKeys)
            }
            for fact in self.facts {
                fact.intern(&interner, &self.symbols)
            }
            for rule in self.rules {
                rule.intern(&interner, &self.symbols, &self.publicKeys)
            }
            for check in self.checks {
                check.intern(&interner, &self.symbols, &self.publicKeys)
            }
            self.context = (self.context ?? "") + (context ?? "")
            if self.context == "" {
                self.context = nil
            }
        }

        init(serializedData data: Data, _ interner: inout BlockInternmentTable) throws {
            let proto = try Biscuit_Format_Schema_Block(serializedBytes: data)
            guard proto.hasVersion else {
                throw Biscuit.ValidationError.missingVersion
            }
            guard proto.version >= 3 && proto.version <= 6 else {
                throw Biscuit.ValidationError.invalidVersion
            }
            self.version = proto.version
            self.symbols = proto.symbols
            self.publicKeys = proto.publicKeys.map { Biscuit.ThirdPartyKey(proto: $0) }
            try interner.extend(self.symbols, self.publicKeys)
            if proto.hasContext {
                self.context = proto.context
            }
            self.checks = try proto.checks.map { try Check(proto: $0, interner: interner) }
            self.facts = try proto.facts.map { try Fact(proto: $0.predicate, interner: interner) }
            self.rules = try proto.rules.map { try Rule(proto: $0, interner: interner) }
            self.trusted = try proto.scope.map { try TrustedScope(proto: $0, interner: interner) }
        }

        func serializedData(_ interner: BlockInternmentTable) throws -> Data {
            try self.proto(interner).serializedData()
        }

        func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Block {
            var proto = Biscuit_Format_Schema_Block()
            proto.symbols = self.symbols
            if let context = self.context {
                proto.context = context
            }
            proto.version = self.version
            proto.checks = self.checks.map { $0.proto(interner) }
            proto.facts = self.facts.map {
                var fact = Biscuit_Format_Schema_Fact()
                fact.predicate = $0.proto(interner)
                return fact
            }
            proto.rules = self.rules.map { $0.proto(interner) }
            proto.scope = self.trusted.map { $0.proto(interner) }
            proto.publicKeys = self.publicKeys.map { $0.proto }
            return proto
        }
    }
}
