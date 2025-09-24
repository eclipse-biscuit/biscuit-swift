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

    /// Deserializes an UnverifiedBiscuit from its base64url representation without
    /// cryptographically verifying that it is authentic.
    ///
    /// - Parameters:
    ///   - base64URLEncoded: the base64url representation of the Biscuit
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if base64url or the
    /// underlying data is not in the proper format
    public init(base64URLEncoded: String) throws {
        // Translate base64url into base64, ignoring padding, as defined in RFC4648.
        let base64Encoded =
            base64URLEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        guard let data = Data(base64Encoded: base64Encoded) else {
            throw Biscuit.ValidationError.invalidBase64URLString
        }

        try self.init(serializedData: data)
    }

    init(
        _ parent: UnverifiedBiscuit,
        _ attenuations: [Biscuit.Block],
        _ interner: InternmentTables,
        _ proof: Biscuit.Proof
    ) {
        self.interner = interner
        self.rootKeyID = parent.rootKeyID
        self.authority = parent.authority
        self.attenuations = attenuations
        self.proof = proof
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
                try externalSignature.isValidSignature(
                    for: block,
                    lastSig: lastBlock.signature,
                    interner: blockInterner
                )
            }
            lastBlock = block
        }
        return Biscuit(unverifiedBiscuit: self)
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    ///   - datalog: the datalog contents of the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated(
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil,
        @Biscuit.DatalogBlock using datalog: () throws -> Biscuit.DatalogBlock
    ) throws -> UnverifiedBiscuit {
        try self.attenuated(using: datalog(), algorithm: algorithm, context: context)
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    ///   - datalog: the datalog contents of the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated<Key: Biscuit.PrivateKey>(
        thirdPartyKey: Key,
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil,
        @Biscuit.DatalogBlock using datalog: () throws -> Biscuit.DatalogBlock
    ) throws -> UnverifiedBiscuit {
        try self.attenuated(
            using: datalog(),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - datalog: the datalog contents of the attenuation, as a String
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated(
        using datalog: String,
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> UnverifiedBiscuit {
        try self.attenuated(
            using: Biscuit.DatalogBlock(datalog),
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - datalog: the datalog contents of the attenuation, as a String
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated<Key: Biscuit.PrivateKey>(
        using datalog: String,
        thirdPartyKey: Key,
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> UnverifiedBiscuit {
        try self.attenuated(
            using: Biscuit.DatalogBlock(datalog),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - datalog: the datalog contents of the attenuation, as a String
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated(
        using datalog: Biscuit.DatalogBlock,
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> UnverifiedBiscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw Biscuit.AttenuationError.cannotAttenuateSealedToken
        }
        var interner = self.interner
        var attenuation = datalog
        attenuation.attachToBiscuit(interner: &interner.primary, context: context)
        let nextKey = Biscuit.InternalPrivateKey(algorithm: algorithm)
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        var attenuations = self.attenuations
        try attenuations.append(
            Biscuit.Block(
                datalog: attenuation,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: lastSig,
                externalSignature: nil,
                interner: interner.primary
            )
        )
        return UnverifiedBiscuit(self, attenuations, interner, .nextSecret(nextKey))
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - datalog: the datalog contents of the attenuation
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated<Key: Biscuit.PrivateKey>(
        using datalog: Biscuit.DatalogBlock,
        thirdPartyKey: Key,
        algorithm: Biscuit.SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> UnverifiedBiscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw Biscuit.AttenuationError.cannotAttenuateSealedToken
        }
        var blockInterner = BlockInternmentTable()
        var attenuation = datalog
        attenuation.attachToBiscuit(interner: &blockInterner, context: context)
        let nextKey = Biscuit.InternalPrivateKey(algorithm: algorithm)
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        var attenuations = self.attenuations
        let externalSignature = try Biscuit.Block.ExternalSignature(
            block: attenuation,
            lastSig: lastSig,
            thirdPartyKey: thirdPartyKey,
            interner: blockInterner
        )
        try attenuations.append(
            Biscuit.Block(
                datalog: attenuation,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: lastSig,
                externalSignature: externalSignature,
                interner: blockInterner
            )
        )
        var interner = self.interner
        interner.setBlockTable(blockInterner, for: attenuations.count)
        return UnverifiedBiscuit(self, attenuations, interner, .nextSecret(nextKey))
    }

    /// Seal this Biscuit, producing a new Biscuit which cannot be attenuated further. This Biscuit
    /// remains unchanged.
    ///
    /// - Returns: the sealed Biscuit
    /// - Throws: Signing may throw an error
    public func sealed() throws -> UnverifiedBiscuit {
        if case .nextSecret(let key) = self.proof {
            let sig = try key.sealingSignature(
                for: self.attenuations.last ?? self.authority,
                interner: self.interner.blockTable(for: self.attenuations.count)
            )
            return UnverifiedBiscuit(self, self.attenuations, self.interner, .finalSignature(sig))
        } else {
            return self
        }
    }

    /// Serialize this UnverifiedBiscuit to its data representation
    /// - Returns: the data representation of this Biscuit
    /// - Throws: May throw an error if protobuf serialization fails
    public func serializedData() throws -> Data {
        try self.proto().serializedData()
    }

    /// Serialize this UnverifiedBiscuit to its base64url encoded representation
    /// - Returns: the base64url encoded representation of this Biscuit
    /// - Throws: May thow an error if protobuf serialization fails
    public func base64URLEncoded() throws -> String {
        let base64Encoded = try self.proto().serializedData().base64EncodedString()
        // Translate base64 into base64url, ignoring padding, as defined in RFC4648.
        return
            base64Encoded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
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
