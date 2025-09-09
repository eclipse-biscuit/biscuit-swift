/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
/// A predicate that can be used in a Rule, Check, or Policy
public struct Predicate: Sendable, Hashable, CustomStringConvertible {
    /// The name of this predicate
    public var name: String
    /// The terms this predicate contains
    public var terms: [Term]

    /// Construct a predicate
    /// - Parameters:
    ///   - name: the name of this fact
    ///   - terms: the terms that this fact contains
    public init<each T: TermConvertible>(_ name: String, _ terms: repeat each T) {
        self.name = name
        var finalTerms: [Term] = []
        repeat finalTerms.append((each terms).term)
        self.terms = finalTerms
    }

    /// Construct a predicate by parsing a String of Datalog
    /// - Parameters:
    ///   - datalog: the datalog that will be parsed
    /// - Throws: Throws a `DatalogError` on a parsing error
    public init(_ datalog: String) throws {
        self = try Parser.predicate(using: datalog)
    }

    init(_ name: String, _ terms: [Term]) {
        self.name = name
        self.terms = terms
    }

    init(proto: Biscuit_Format_Schema_Predicate, interner: BlockInternmentTable) throws {
        guard proto.hasName else {
            throw Biscuit.ValidationError.missingPredicate
        }
        self.name = try interner.lookupSymbol(Int(proto.name))
        self.terms = try proto.terms.map { try Term(proto: $0, interner: interner) }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        interner.intern(self.name, &locals)
        for term in self.terms {
            term.intern(&interner, &locals)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Predicate {
        var proto = Biscuit_Format_Schema_Predicate()
        proto.name = UInt64(interner.symbolIndex(for: self.name))
        proto.terms = self.terms.map { $0.proto(interner) }
        return proto
    }

    func makeConcrete(variables: [String: Value]) throws -> Fact {
        try Fact(name: self.name, values: self.terms.map { try $0.makeConcrete(variables: variables) })
    }

    func forceConcrete() throws -> Fact {
        try Fact(
            name: self.name,
            values: self.terms.map {
                switch $0.wrapped {
                case .value(let v): return v
                case .variable: throw Biscuit.DatalogError.variableInFact
                }
            }
        )

    }

    static var query: Biscuit_Format_Schema_Predicate {
        var proto = Biscuit_Format_Schema_Predicate()
        proto.name = UInt64(27)
        return proto
    }

    public var description: String {
        "\(name)(\(terms.map { "\($0)" }.joined(separator: ", ")))"
    }
}
