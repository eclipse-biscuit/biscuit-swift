/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension Biscuit {
    /// Generates a request for a third party to attenuate this token
    public func generateThirdPartyBlockRequest() -> ThirdPartyBlockRequest {
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        return ThirdPartyBlockRequest(previousSignature: lastSig)
    }

    /// Attenuate a token with a `ThirdPartyBlockContents`
    /// - Parameter contents: the contents of the block that will be used to attenuate this token
    /// - Parameter algorithm: the algorithm that will be used for the next attenuation
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated(
        using contents: ThirdPartyBlockContents,
        algorithm: SigningAlgorithm = .ed25519
    ) throws -> Biscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw AttenuationError.cannotAttenuateSealedToken
        }
        let nextKey = InternalPrivateKey(algorithm: algorithm)
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        let attenuation = try Block(
            datalog: contents.payload,
            nextKey: nextKey.publicKey,
            lastKey: lastKey,
            lastSig: lastSig,
            externalSignature: contents.externalSignature,
            interner: contents.interner
        )
        try contents.externalSignature.isValidSignature(
            for: attenuation,
            lastSig: lastSig,
            interner: contents.interner
        )
        let attenuations = self.attenuations + [attenuation]
        var interner = self.interner
        interner.setBlockTable(contents.interner, for: attenuations.count)
        return Biscuit(self, attenuations, interner, .nextSecret(nextKey))
    }

    /// A request for a third party to attenuate this token
    ///
    /// This request can be sent from a holder of a biscuit to another entity and that entity can
    /// sign an attenuation to that biscuit with a third party key, without revealing the entire
    /// biscuit to that entity.
    public struct ThirdPartyBlockRequest: Sendable, Hashable {
        var previousSignature: Data

        /// Deserializes a ThirdPartyBlockRequest from its data representation.
        /// - Throws: May throw an error during deserialization
        public init(serializedData data: Data) throws {
            let proto = try Biscuit_Format_Schema_ThirdPartyBlockRequest(serializedBytes: data)
            guard proto.hasPreviousSignature else {
                throw ValidationError.missingPreviousSignature
            }
            self.previousSignature = proto.previousSignature
        }

        init(previousSignature: Data) {
            self.previousSignature = previousSignature
        }

        /// Generates a block that can be used to attenuate a Biscuit.
        /// - Parameter privateKey: The key that will be used to sign this block
        /// - Parameter context: Any context that will be added to this block.
        /// - Parameter datalog: The datalog content of this block.
        /// - Throws: May throw an error during signing
        public func generateBlock<Key: PrivateKey>(
            privateKey: Key,
            context: String? = nil,
            @DatalogBlock using datalog: () throws -> DatalogBlock
        ) throws -> ThirdPartyBlockContents {
            try ThirdPartyBlockContents(using: datalog(), privateKey, context, self)
        }

        /// Generates a block that can be used to attenuate a Biscuit.
        /// - Parameter datalog: The datalog content of this block as a String.
        /// - Parameter privateKey: The key that will be used to sign this block
        /// - Parameter context: Any context that will be added to this block.
        /// - Returns: the ThirdPartyBlockContents
        /// - Throws: May throw an error during signing and may throw a `DatalogError` if the
        /// datalog string cannot be parsed
        public func generateBlock<Key: PrivateKey>(
            using datalog: String,
            privateKey: Key,
            context: String? = nil
        ) throws -> ThirdPartyBlockContents {
            try ThirdPartyBlockContents(using: DatalogBlock(datalog), privateKey, context, self)
        }

        public func generateBlock<Key: PrivateKey>(
            using datalog: DatalogBlock,
            privateKey: Key,
            context: String? = nil
        ) throws -> ThirdPartyBlockContents {
            try ThirdPartyBlockContents(using: datalog, privateKey, context, self)
        }

        /// Serializes this ThirdPartyBlockRequest to its data representation
        /// Returns: the data representation of this ThirdPartyBlockRequest
        /// Throws: May throw a serialization error
        public func serializedData() throws -> Data {
            try self.proto.serializedData()
        }

        var proto: Biscuit_Format_Schema_ThirdPartyBlockRequest {
            var proto = Biscuit_Format_Schema_ThirdPartyBlockRequest()
            proto.previousSignature = self.previousSignature
            return proto
        }
    }

    /// The contents of a block signed by a third party with a `ThirdPartyBlockRequest`
    public struct ThirdPartyBlockContents: Sendable, Hashable {
        var payload: DatalogBlock
        var externalSignature: Block.ExternalSignature
        var interner: BlockInternmentTable

        /// Deserializes a ThirdPartyBlockContents from its data representation.
        /// - Throws: May throw an error during deserialization
        public init(serializedData data: Data) throws {
            let proto = try Biscuit_Format_Schema_ThirdPartyBlockContents(serializedBytes: data)
            guard proto.hasPayload else {
                throw ValidationError.missingPayload
            }
            guard proto.hasExternalSignature else {
                throw ValidationError.missingExternalSignature
            }
            self.interner = BlockInternmentTable()
            self.payload = try DatalogBlock(serializedData: proto.payload, &self.interner)
            self.externalSignature = try Block.ExternalSignature(proto: proto.externalSignature)
        }

        init<Key: PrivateKey>(
            using datalog: DatalogBlock,
            _ key: Key,
            _ context: String?,
            _ request: ThirdPartyBlockRequest
        ) throws {
            self.interner = BlockInternmentTable()
            self.payload = datalog
            self.payload.attachToBiscuit(interner: &self.interner, context: context)
            self.externalSignature = try Block.ExternalSignature(
                block: self.payload,
                lastSig: request.previousSignature,
                thirdPartyKey: key,
                interner: self.interner
            )
        }

        /// Serializes this ThirdPartyBlockContents to its data representation
        /// Returns: the data representation of this ThirdPartyBlockContents
        /// Throws: May throw a serialization error
        public func serializedData() throws -> Data {
            try self.proto().serializedData()
        }

        func proto() throws -> Biscuit_Format_Schema_ThirdPartyBlockContents {
            var proto = Biscuit_Format_Schema_ThirdPartyBlockContents()
            proto.payload = try self.payload.serializedData(self.interner)
            proto.externalSignature = self.externalSignature.proto
            return proto
        }
    }
}
