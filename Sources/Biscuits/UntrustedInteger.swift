/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Deserialization reads the Datalog payload of a block before that block's signature has been
// verified, so every integer it takes off the protobuf wire is attacker controlled. `Int.init(_:)`
// traps when a value is not representable as an `Int`, and `Array`'s subscript traps when an index
// is out of bounds; either one terminates the process. Deserialization uses the helpers below
// instead, so that malformed data throws a `ValidationError` the caller can handle.

extension BinaryInteger {
    /// This value as an `Int`, for use as an index into a table.
    ///
    /// - Returns: this value as an `Int`
    /// - Throws: Throws a `ValidationError` if this value is not representable as an `Int`
    func validatedIndex() throws -> Int {
        guard let index = Int(exactly: self) else {
            throw Biscuit.ValidationError.invalidIndex
        }
        return index
    }
}

extension Array {
    /// The element at `index`, bounds checked at both ends.
    ///
    /// - Parameter index: the index to look up
    /// - Returns: the element at `index`
    /// - Throws: Throws a `ValidationError` if `index` is out of bounds
    func element(at index: Int) throws -> Element {
        guard self.indices.contains(index) else {
            throw Biscuit.ValidationError.invalidIndex
        }
        return self[index]
    }
}
