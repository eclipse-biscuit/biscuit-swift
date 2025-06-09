/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
/// A trusted scope for a policy or rule.
public struct TrustedScope: Equatable, Sendable, Hashable, CustomStringConvertible, TrustedScopeConvertible {
    internal enum Wrapped: Hashable {
        case authority
        case previous
        case publicKey(Biscuit.ThirdPartyKey)
    }
    let wrapped: Wrapped

    init(_ wrapped: Wrapped) {
        self.wrapped = wrapped
    }

    init(proto: Biscuit_Format_Schema_Scope, interner: BlockInternmentTable) throws {
        self.wrapped = switch proto.content {
            case .scopeType(.authority): .authority
            case .scopeType(.previous): .previous
            case .publicKey(let key): try .publicKey(interner.lookupPublicKey(Int(key)))
            case .none: throw Biscuit.ValidationError.missingScope
        }
    }

    static func publicKey<Key: Biscuit.PublicKey>(_ key: Key) -> TrustedScope {
        TrustedScope(.publicKey(Biscuit.ThirdPartyKey(key: key)))
    }

    func intern(_ interner: inout BlockInternmentTable, _ keys: inout [Biscuit.ThirdPartyKey]) {
        if case .publicKey(let key) = self.wrapped {
            interner.intern(key, &keys)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_Scope {
        var proto = Biscuit_Format_Schema_Scope()
        switch self.wrapped {
            case .authority: proto.scopeType = .authority
            case .previous: proto.scopeType = .previous
            case .publicKey(let key): proto.publicKey = Int64(interner.publicKeyIndex(for: key))
        }
        return proto
    }

    public var description: String {
        switch self.wrapped {
            case .authority: "authority"
            case .previous: "previous"
            case .publicKey(let key): "\(key)"
        }
    }

    public var trustedScope: TrustedScope { self }
}

/// Anything which can be converted into a TrustedScope
public protocol TrustedScopeConvertible {
    var trustedScope: TrustedScope { get }
}

extension TrustedScopeConvertible where Self == TrustedScope {
    /// The authority block and the authorizer
    public static var authority: TrustedScope { TrustedScope(.authority) }
    /// Any block previous to this block
    public static var previous: TrustedScope { TrustedScope(.previous) }
}

extension Biscuit.PublicKey {
    public var trustedScope: TrustedScope { .publicKey(self) }
}
extension Biscuit.ThirdPartyKey: TrustedScopeConvertible  {
    public var trustedScope: TrustedScope {
        TrustedScope(.publicKey(self))
    }
}

/// A statement that other statements in this block trust these scopes
public struct Trusting {
    let trusted: [TrustedScope]

    /// Construct a Trusting statement from a sequence of TrustedScopeConvertibles
    /// - Parameter trusting: a scope to be trusted
    public init<each T: TrustedScopeConvertible>(_ trusting: repeat each T) {
        var trusted: [TrustedScope] = []
        repeat trusted.append((each trusting).trustedScope)
        self.trusted = trusted
    }

    /// Construct a Trusting statement by parsing a String as Datalog
    /// - Parameter datalog: the Datalog of this Trusting statement
    public init(_ datalog: String) throws {
        let parser = try Parser.forTrusting(using: datalog)
        self.trusted = parser.origins
    }
}
