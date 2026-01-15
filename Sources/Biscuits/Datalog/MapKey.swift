/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A Value that can be used as a key in a map
public struct MapKey: MapKeyConvertible, ValueConvertible, TermConvertible, ExpressionConvertible, Hashable, Sendable,
    CustomStringConvertible
{
    internal enum Wrapped: Hashable {
        case integer(Int64)
        case string(String)
    }
    let wrapped: Wrapped

    init(proto: Biscuit_Format_Schema_MapKey, interner: InternmentTable) throws {
        self.wrapped =
            switch proto.content {
            case .integer(let i): .integer(i)
            case .string(let s): try .string(interner.lookupSymbol(Int(s)))
            case .none: throw Biscuit.ValidationError.missingTerm
            }
    }

    /// An integer MapKey
    public init(_ integer: Int) {
        self.wrapped = .integer(Int64(integer))
    }

    /// A string MapKey
    public init(_ string: String) {
        self.wrapped = .string(string)
    }

    init(_ wrapped: Wrapped) {
        self.wrapped = wrapped
    }

    func intern(_ interner: inout InternmentTable, _ locals: inout [String]) -> Biscuit_Format_Schema_MapKey {
        var proto = Biscuit_Format_Schema_MapKey()
        switch self.wrapped {
        case .string(let s): proto.string = UInt64(interner.intern(s, &locals))
        case .integer(let i): proto.integer = Int64(i)
        }
        return proto
    }

    public var description: String {
        switch self.wrapped {
        case .string(let s): "\"\(s)\""
        case .integer(let i): "\(i)"
        }
    }

    public var mapKey: MapKey { self }

    public var value: Value {
        switch self.wrapped {
        case .integer(let i): Value(.integer(i))
        case .string(let s): Value(s)
        }
    }
}

/// Anything which can be converted into a MapKey
public protocol MapKeyConvertible: ValueConvertible {
    var mapKey: MapKey { get }
}

extension Int: MapKeyConvertible {
    public var mapKey: MapKey { MapKey(self) }
}

extension String: MapKeyConvertible {
    public var mapKey: MapKey { MapKey(self) }
}
