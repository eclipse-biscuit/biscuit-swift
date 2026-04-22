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
    let interner: InternmentTable
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
        var interner = InternmentTable()
        self.authority = try Biscuit.Block.unverifiedAuthority(proto: proto.authority, interner: &interner)
        var lastBlock = self.authority
        self.attenuations = try proto.blocks.map {
            lastBlock = try Biscuit.Block.unverifiedAttenuation(proto: $0, interner: &interner)
            return lastBlock
        }
        self.interner = interner
        self.proof = try Biscuit.Proof(proto: proto.proof, algorithm: lastBlock.nextKey.algorithm)
    }

    /// Deserializes an UnverifiedBiscuit from its base64url representation without
    /// cryptographically verifying that it is authentic.
    ///
    /// - Parameters:
    ///   - base64URLEncoded: the base64url representation of the Biscuit
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if base64url or the
    /// underlying data is not in the proper format
    public init(base64URLEncoded: String) throws {
        let data = try Biscuits.base64URLDecoded(base64URLEncoded)
        try self.init(serializedData: data)
    }

    init(
        _ parent: UnverifiedBiscuit,
        _ attenuations: [Biscuit.Block],
        _ interner: InternmentTable,
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
        let signatureInput = self.authority.signatureInput()
        guard key.isValidSignature(self.authority.signature, for: signatureInput) else {
            throw Biscuit.ValidationError.invalidSignature
        }
        var lastBlock = self.authority
        for block in self.attenuations {
            let signatureInput = block.signatureInput(lastSig: lastBlock.signature)
            guard lastBlock.nextKey.isValidSignature(block.signature, for: signatureInput) else {
                throw Biscuit.ValidationError.invalidSignature
            }
            if let externalSignature = block.externalSignature {
                try externalSignature.isValidSignature(
                    for: block,
                    lastSig: lastBlock.signature,
                )
            }
            lastBlock = block
        }
        try self.proof.isValidProof(for: lastBlock)
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
        try self.attenuated(using: Biscuit.DatalogBlock(context: context, datalog), algorithm: algorithm)
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
            using: Biscuit.DatalogBlock(context: context, datalog),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
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
            using: Biscuit.DatalogBlock(datalog, context: context),
            algorithm: algorithm,
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
            using: Biscuit.DatalogBlock(datalog, context: context),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
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
    ) throws -> UnverifiedBiscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw Biscuit.AttenuationError.cannotAttenuateSealedToken
        }
        var interner = self.interner
        let nextKey = Biscuit.InternalPrivateKey(algorithm: algorithm)
        var attenuations = self.attenuations
        try attenuations.append(
            Biscuit.Block(
                datalog: datalog,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: self.lastBlock.signature,
                interner: &interner
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
    ) throws -> UnverifiedBiscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw Biscuit.AttenuationError.cannotAttenuateSealedToken
        }
        let nextKey = Biscuit.InternalPrivateKey(algorithm: algorithm)
        var attenuations = self.attenuations
        try attenuations.append(
            Biscuit.Block(
                datalog: datalog,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: self.lastBlock.signature,
                thirdPartyKey: thirdPartyKey,
            )
        )
        return UnverifiedBiscuit(self, attenuations, self.interner, .nextSecret(nextKey))
    }

    /// Seal this Biscuit, producing a new Biscuit which cannot be attenuated further. This Biscuit
    /// remains unchanged.
    ///
    /// - Returns: the sealed Biscuit
    /// - Throws: Signing may throw an error
    public func sealed() throws -> UnverifiedBiscuit {
        if case .nextSecret(let key) = self.proof {
            let sig = try key.sealingSignature(for: self.lastBlock)
            return UnverifiedBiscuit(self, self.attenuations, self.interner, .finalSignature(sig))
        } else {
            return self
        }
    }

    /// Serialize this UnverifiedBiscuit to its data representation
    /// - Returns: the data representation of this Biscuit
    /// - Throws: May throw an error if protobuf serialization fails
    public func serializedData() throws -> Data {
        try self.proto.serializedData()
    }

    /// Serialize this UnverifiedBiscuit to its base64url encoded representation
    /// - Returns: the base64url encoded representation of this Biscuit
    /// - Throws: May thow an error if protobuf serialization fails
    public func base64URLEncoded() throws -> String {
        let data = try self.serializedData()
        return Biscuits.base64URLEncoded(data)
    }

    var proto: Biscuit_Format_Schema_Biscuit {
        var proto = Biscuit_Format_Schema_Biscuit()
        if let rootKeyID = self.rootKeyID {
            proto.rootKeyID = rootKeyID.rawValue
        }
        proto.authority = self.authority.proto
        proto.blocks = self.attenuations.map { $0.proto }
        proto.proof = self.proof.proto
        return proto
    }

    /// Generates a request for a third party to attenuate this token
    public func generateThirdPartyBlockRequest() -> Biscuit.ThirdPartyBlockRequest {
        Biscuit.ThirdPartyBlockRequest(previousSignature: self.lastBlock.signature)
    }

    /// Attenuate a token with a `ThirdPartyBlockContents`
    /// - Parameter contents: the contents of the block that will be used to attenuate this token
    /// - Parameter algorithm: the algorithm that will be used for the next attenuation
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated(
        using contents: Biscuit.ThirdPartyBlockContents,
        algorithm: Biscuit.SigningAlgorithm = .ed25519
    ) throws -> UnverifiedBiscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw Biscuit.AttenuationError.cannotAttenuateSealedToken
        }
        let nextKey = Biscuit.InternalPrivateKey(algorithm: algorithm)
        let attenuation = try Biscuit.Block(
            contents: contents,
            nextKey: nextKey.publicKey,
            lastKey: lastKey,
            lastSig: self.lastBlock.signature
        )
        try contents.externalSignature.isValidSignature(
            for: attenuation,
            lastSig: self.lastBlock.signature,
        )
        let attenuations = self.attenuations + [attenuation]
        return UnverifiedBiscuit(self, attenuations, self.interner, .nextSecret(nextKey))
    }

    /// Whether or not this UnverifiedBiscuit has been sealed
    public var isSealed: Bool { self.proof.isSealed }

    var lastBlock: Biscuit.Block {
        self.attenuations.last ?? self.authority
    }
}
