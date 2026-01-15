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
            let datalog = try datalog()
            self.checks = datalog.checks
            self.facts = datalog.facts
            self.rules = datalog.rules
            self.trusted = datalog.trusted
            self.context = context
        }

        /// Construct a DatalogBlock from a String of Datalog
        ///
        /// - Parameter context: the context that will be included with this DatalogBlock
        /// - Parameter datalog: the Datalog contents of this DatalogBlock as a String
        public init(_ datalog: String, context: String? = nil) throws {
            let parser = try Parser.forDatalogBlock(using: datalog)
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

        func serializeInBiscuit(interner: inout InternmentTable) throws -> Data {
            var proto = Biscuit_Format_Schema_Block()
            var symbols: [String] = []
            var publicKeys: [ThirdPartyKey] = []
            if let context = self.context {
                proto.context = context
            }
            proto.version = 6
            proto.scope = self.trusted.map { $0.intern(&interner, &publicKeys) }
            proto.facts = self.facts.map { $0.intern(&interner, &symbols) }
            proto.rules = self.rules.map { $0.intern(&interner, &symbols, &publicKeys) }
            proto.checks = self.checks.map { $0.intern(&interner, &symbols, &publicKeys) }
            proto.symbols = symbols
            proto.publicKeys = publicKeys.map { $0.proto }
            return try proto.serializedData()
        }

        init(serializedData data: Data, _ interner: inout InternmentTable) throws {
            let proto = try Biscuit_Format_Schema_Block(serializedBytes: data)
            guard proto.hasVersion else {
                throw Biscuit.ValidationError.missingVersion
            }
            guard proto.version >= 3 && proto.version <= 6 else {
                throw Biscuit.ValidationError.invalidVersion
            }
            let symbols = proto.symbols
            let publicKeys = proto.publicKeys.map { Biscuit.ThirdPartyKey(proto: $0) }
            try interner.extend(symbols, publicKeys)
            if proto.hasContext {
                self.context = proto.context
            } else {
                self.context = nil
            }
            self.checks = try proto.checks.map { try Check(proto: $0, interner: interner) }
            self.facts = try proto.facts.map { try Fact(proto: $0.predicate, interner: interner) }
            self.rules = try proto.rules.map { try Rule(proto: $0, interner: interner) }
            self.trusted = try proto.scope.map { try TrustedScope(proto: $0, interner: interner) }
        }
    }
}
