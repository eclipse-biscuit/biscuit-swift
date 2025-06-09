/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A fact that is known to be true
public struct Fact: Sendable, Hashable, CustomStringConvertible {
    /// The name of this fact
    public var name: String
    /// The values in this fact
    public var values: [Value]

    /// Construct a fact
    /// - Parameters:
    ///   - name: the name of this fact
    ///   - values: the values that this fact contains
    public init<each T: ValueConvertible>(_ name: String, _ values: repeat each T) {
        self.name = name
        var finalTerms: [Value] = []
        repeat finalTerms.append((each values).value)
        self.values = finalTerms
    }

    /// Construct a fact by parsing a String of Datalog
    /// - Parameters:
    ///   - datalog: the datalog that will be parsed
    /// - Throws: Throws a `DatalogError` on a parsing error
    public init(_ datalog: String) throws {
        let parser = try Parser.forFact(using: datalog)
        self = parser.facts[0]
    }

    init(name: String, values: [Value]) {
        self.name = name
        self.values = values
    }

    init(index: Int, revocationID: Data) {
        self.name = "revocation_id"
        self.values = [index.value, revocationID.value]
    }

    init(proto: Biscuit_Format_Schema_PredicateV2, interner: BlockInternmentTable) throws {
        guard proto.hasName else {
            throw Biscuit.ValidationError.missingPredicate
        }
        self.name = try interner.lookupSymbol(Int(proto.name))
        self.values = try proto.terms.map { try Value(proto: $0, interner: interner) }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        interner.intern(self.name, &locals)
        for values in self.values {
            values.intern(&interner, &locals)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_PredicateV2 {
        var proto = Biscuit_Format_Schema_PredicateV2()
        proto.name = UInt64(interner.symbolIndex(for: self.name))
        proto.terms = self.values.map { $0.proto(interner) }
        return proto
    }

    func supportsWithVariables(_ predicate: Predicate, _ vars: [String: Value]) -> [String: Value]? {
        var vars = vars
        for (predicateTerm, factValue) in zip(predicate.terms, self.values) {
            switch predicateTerm.wrapped {
                case .value(let predicateValue): guard predicateValue == factValue else { return nil }
                case .variable(let variable):
                    if let definedValue = vars[variable] {
                        guard definedValue == factValue else { return nil }
                    } else {
                        vars[variable] = factValue
                    }
            }
        }
        return vars
    }

    /// This fact as a predicate
    public var predicate: Predicate {
        Predicate(self.name, self.values.map { $0.term })
    }

    public var description: String {
        "\(name)(\(values.map { "\($0)" }.joined(separator: ", ")))"
    }
}
