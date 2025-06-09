/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A check, contained in a Biscuit or an Authorizer, which must succeed for a biscuit to be valid.
public struct Check: Sendable, Hashable, CustomStringConvertible {
    // NB: This property must be optional because it didn't originally exist in the
    // specification; older versions of biscuits will omit the field from their protobuf (whichj
    // should be interpreted as check if). Because these checks are signed, we need to continue
    // to generate protobuf without a kind for those checks or signature verification will fail.
    let _kind: Kind?

    /// The queries of this Check. For the check to pass, at least one must be true.
    public let queries: [Biscuit.Query]

    /// A variety of Check
    public struct Kind: Sendable, Hashable, CustomStringConvertible {
        enum Wrapped: Hashable { case one, all, reject }
        let wrapped: Wrapped

        /// The kind of a "check if" Check
        public static var checkIf: Kind { Kind(wrapped: .one) }
        /// The kind of a "check all" Check
        public static var checkAll: Kind { Kind(wrapped: .all) }
        /// The kind of a "reject if" Check
        public static var rejectIf: Kind { Kind(wrapped: .reject) }

        public var description: String {
            switch self.wrapped {
                case .one: "check if"
                case .all: "check all"
                case .reject: "reject if"
            }
        }
    }

    /// Construct a check by parsing a String of Datalog
    /// - Parameters:
    ///   - datalog: the datalog that will be parsed
    /// - Throws: Throws a `DatalogError` on a parsing error
    public init(_ datalog: String) throws {
        let parser = try Parser.forQuery(using: datalog)
        self = parser.checks[0]
    }

    /// Construct a "check if" check
    ///
    /// - Parameters:
    ///   - trusting: any scopes that will trusted for this check
    ///   - predicates: the predicates of this check
    public static func checkIf<each T: TrustedScopeConvertible>(
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) rethrows -> Check {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try Check(kind: .checkIf, trusting: scopes, predicates())
    }

    /// Construct a "check all" check
    ///
    /// - Parameters:
    ///   - trusting: any scopes that will trusted for this check
    ///   - predicates: the predicates of this check
    public static func checkAll<each T: TrustedScopeConvertible>(
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) rethrows -> Check {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try Check(kind: .checkAll, trusting: scopes, predicates())
    }

    /// Construct a "reject if" check
    ///
    /// - Parameters:
    ///   - trusting: any scopes that will trusted for this check
    ///   - predicates: the predicates of this check
    public static func rejectIf<each T: TrustedScopeConvertible>(
        trusting: repeat each T,
        @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
    ) rethrows -> Check {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try Check(kind: .rejectIf, trusting: scopes, predicates())
    }

    /// Construct a check to determine that the token expires at a given Date.
    ///
    /// The body of this check will be equivalent to: `check if time($time), $time <= expirationDate;`
    ///
    /// - Parameter at: the Date at which this token expires
    public static func tokenExpires(at expirationDate: Date) -> Check {
        Check.checkIf {
            Predicate("time", Term(variable: "time"))
            Term(variable: "time").lessThanOrEqual(expirationDate)
        }
    }

    init(kind: Kind, trusting: [TrustedScope] = [], _ predicates: Biscuit.StatementBuilder) {
        self._kind = kind
        self.queries = [Biscuit.Query(predicates.predicates, predicates.expressions, trusting)]
    }

    init(_ kind: Kind, _ queries: [Biscuit.Query]) {
        self._kind = kind
        self.queries = queries
    }

    init(proto: Biscuit_Format_Schema_CheckV2, interner: BlockInternmentTable) throws {
        self.queries = try proto.queries.map { try Biscuit.Query(proto: $0, interner: interner) }
        if proto.hasKind {
            self._kind = switch proto.kind {
                case .one: .checkIf
                case .all: .checkAll
                case .reject: .rejectIf
            }
        } else {
            self._kind = nil
        }
    }

    public static func == (lhs: Check, rhs: Check) -> Bool {
        lhs.kind == rhs.kind && lhs.queries == rhs.queries
    }

    func intern(
        _ interner: inout BlockInternmentTable,
        _ symbols: inout [String],
        _ publicKeys: inout [Biscuit.ThirdPartyKey]
    ) {
        for query in self.queries {
            query.intern(&interner, &symbols, &publicKeys)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_CheckV2 {
        var proto = Biscuit_Format_Schema_CheckV2()
        proto.queries = self.queries.map { $0.proto(interner) }
        if let kind = self._kind {
            proto.kind = switch kind.wrapped {
                case .one: .one
                case .all: .all
                case .reject: .reject
            }
        }
        return proto
    }

    /// The kind of this check
    public var kind: Kind { self._kind ?? .checkIf }

    public var description: String {
        return "\(kind) \(queries.map { $0.description }.joined(separator: ", "))"
    }
}
