/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An UnverifiedBiscuit is a biscuit which has not been cryptographically verified.
public struct UnverifiedBiscuit: Sendable, Hashable {
    let interner: InternmentTables
    let proof: Biscuit.Proof

    /// The ID of the key used to sign the authority block of this Biscuit, if one is specified
    public var rootKeyID: Biscuit.RootKeyID?
    /// The authority block of this Biscuit
    public let authority: Biscuit.Block
    /// All of the attenuations on this UnverifiedBiscuit
    public let attenuations: [Biscuit.Block]

    /// Deserializes an UnverifiedBiscuit from its serialized representation without
    /// cryptographically verifying that it is authentic.
    ///
    /// - Parameters:
    ///   - serializedData: the serialized representation of the Biscuit
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if the
    /// serializedData is not in the proper format
    public init(serializedData: Data) throws {
        let proto = try Biscuit_Format_Schema_Biscuit(serializedBytes: serializedData)
        guard proto.hasAuthority else {
            throw Biscuit.ValidationError.missingAuthority
        }
        if proto.hasRootKeyID {
            self.rootKeyID = Biscuit.RootKeyID(Int(proto.rootKeyID))
        } else {
            self.rootKeyID = nil
        }
        var interner = InternmentTables()
        self.authority = try Biscuit.Block(proto: proto.authority, interner: &interner)
        var lastBlock = self.authority
        self.attenuations = try proto.blocks.enumerated().map {
            lastBlock = try Biscuit.Block(proto: $1, blockID: $0 + 1, interner: &interner)
            return lastBlock
        }
        self.proof = try Biscuit.Proof(proto: proto.proof, algorithm: lastBlock.nextKey.algorithm)
        self.interner = interner
    }

    /// Verify a biscuit using a specific key, returning a Biscuit now that verification is
    /// complete.
    ///
    /// - Parameters using: the key used to verify this biscuit
    /// - Throw: A ValidationError is thrown if any signature is invalid
    public func verify<Key: Biscuit.PublicKey>(using key: Key) throws -> Biscuit {
        let signatureInput = try self.authority.signatureInput(interner: interner.primary)
        guard key.isValidSignature(self.authority.signature, for: signatureInput) else {
            throw Biscuit.ValidationError.invalidSignature
        }
        var lastBlock = self.authority
        for (blockID, block) in self.attenuations.enumerated() {
            let blockInterner = interner.blockTable(for: blockID + 1)
            let signatureInput = try block.signatureInput(interner: blockInterner, lastSig: lastBlock.signature)
            guard lastBlock.nextKey.isValidSignature(block.signature, for: signatureInput) else {
                throw Biscuit.ValidationError.invalidSignature
            }
            if let externalSignature = block.externalSignature {
                try externalSignature.isValidSignature(for: block, lastSig: lastBlock.signature, interner: blockInterner)
            }
            lastBlock = block
        }
        return Biscuit(unverifiedBiscuit: self)
    }

    /// Serialize this UnverifiedBiscuit to its data representation
    /// - Returns: the data representation of this Biscuit
    /// - Throws: May throw an error if protobuf serialization fails
    public func serializedData() throws -> Data {
        return try self.proto().serializedData()
    }

    func proto() throws -> Biscuit_Format_Schema_Biscuit {
        var proto = Biscuit_Format_Schema_Biscuit()
        if let rootKeyID = self.rootKeyID {
            proto.rootKeyID = rootKeyID.rawValue
        }
        proto.authority = try self.authority.proto(interner: self.interner.primary)
        proto.blocks = try self.attenuations.enumerated().map {
            try $1.proto(interner: self.interner.blockTable(for: $0))
        }
        proto.proof = self.proof.proto
        return proto
    }

    /// Whether or not this UnverifiedBiscuit has been sealed
    public var isSealed: Bool { self.proof.isSealed }
}
