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

    /// The kind of a MapKey
    public struct Kind: Sendable, Hashable, CustomStringConvertible {
        enum Wrapped: Hashable { case integer, string }
        let wrapped: Wrapped

        init?(content: Biscuit_Format_Schema_MapKey.OneOf_Content?) {
            switch content {
            case .integer: self.wrapped = .integer
            case .string: self.wrapped = .string
            case .none: return nil
            }
        }

        init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }

        /// The kind of an integer MapKey
        public static var integer: Kind { Kind(wrapped: .integer) }
        /// The kind of a string MapKey
        public static var string: Kind { Kind(wrapped: .string) }

        public var description: String {
            switch self.wrapped {
            case .integer: "integer"
            case .string: "string"
            }
        }
    }

    init(proto: Biscuit_Format_Schema_MapKey, interner: InternmentTable, allowList: Biscuit.AllowList.PerBlock) throws {
        if let allowedKinds = allowList.allowedMapKeyTypes, let kind = Kind(content: proto.content) {
            guard allowedKinds.contains(kind) else {
                throw Biscuit.AllowListError.mapKeyTypeNotAllowed
            }
        }
        switch proto.content {
        case .integer(let i): self.wrapped = .integer(i)
        case .string(let s):
            let string = try interner.lookupSymbol(s)
            guard string.utf8.count <= allowList.maximumStringLength else {
                throw Biscuit.AllowListError.stringTooLong
            }
            self.wrapped = .string(string)
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
