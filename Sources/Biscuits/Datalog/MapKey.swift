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
public struct MapKey: MapKeyConvertible, ValueConvertible, TermConvertible, ExpressionConvertible, Hashable, Sendable, CustomStringConvertible {
    internal enum Wrapped: Hashable {
        case integer(Int64)
        case string(String)
    }
    let wrapped: Wrapped

    init(proto: Biscuit_Format_Schema_MapKey, interner: BlockInternmentTable) throws {
        self.wrapped = switch proto.content {
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

    // Intentionally not public and MapKey does not conform to Comparable
    static func < (lhs: MapKey, rhs: MapKey) -> Bool {
        switch (lhs.wrapped, rhs.wrapped) {
            case (.integer(let l), .integer(let r)): return l < r
            case (.string(let l), .string(let r)): return l < r
            case (.integer, .string): return true
            case (.string, .integer): return false
        }
    }

    func intern(_ interner: inout BlockInternmentTable, _ locals: inout [String]) {
        if case .string(let s) = self.wrapped {
            interner.intern(s, &locals)
        }
    }

    func proto(_ interner: BlockInternmentTable) -> Biscuit_Format_Schema_MapKey {
        var proto = Biscuit_Format_Schema_MapKey()
        switch self .wrapped {
            case .string(let s): proto.string = UInt64(interner.symbolIndex(for: s))
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

extension Biscuit_Format_Schema_MapEntry: Comparable {
    static func < (lhs: Biscuit_Format_Schema_MapEntry, rhs: Biscuit_Format_Schema_MapEntry) -> Bool {
        lhs.key < rhs.key || (lhs.key == rhs.key && lhs.value < rhs.value)
    }
}

extension Biscuit_Format_Schema_MapKey: Comparable {
    static func < (lhs: Biscuit_Format_Schema_MapKey, rhs: Biscuit_Format_Schema_MapKey) -> Bool {
        switch (lhs.content, rhs.content) {
            case (.integer(let l), .integer(let r)): return l < r
            case (.string(let l), .string(let r)): return l < r
            case (.none, .none): return true
            case (.integer, .string): return true
            case (.string, .integer): return false
            case (.none, _): return true
            case (_, .none): return false
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
