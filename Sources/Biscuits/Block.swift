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
    /// A block of datalog (either the authority block or an attenuation) within a Biscuit
    public struct Block: Sendable, Hashable {
        /// The Datalog contents of this block
        public let datalog: DatalogBlock
        let nextKey: InternalPublicKey
        let version: UInt32?
        let serializedDatalog: Data
        let signature: Data
        let externalSignature: ExternalSignature?

        init<Key: PrivateKey>(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            key: Key,
            interner: inout InternmentTable
        ) throws {
            self.datalog = datalog
            self.nextKey = nextKey
            self.version = 1
            self.serializedDatalog = try datalog.serializeInBiscuit(interner: &interner)
            self.externalSignature = nil
            self.signature = try key.signature(
                for: SignatureV1.blockSignatureInput(
                    payload: self.serializedDatalog,
                    nextKey: self.nextKey,
                    prevSig: nil,
                    externalSig: nil
                )
            )
        }

        init(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            lastKey: InternalPrivateKey,
            lastSig: Data,
            interner: inout InternmentTable
        ) throws {
            self.datalog = datalog
            self.nextKey = nextKey
            self.version = 1
            self.serializedDatalog = try datalog.serializeInBiscuit(interner: &interner)
            self.externalSignature = nil
            self.signature = try lastKey.signature(
                for: SignatureV1.blockSignatureInput(
                    payload: self.serializedDatalog,
                    nextKey: self.nextKey,
                    prevSig: lastSig,
                    externalSig: nil
                )
            )
        }

        init<Key: PrivateKey>(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            lastKey: InternalPrivateKey,
            lastSig: Data,
            thirdPartyKey: Key,
        ) throws {
            var interner = InternmentTable()
            self.datalog = datalog
            self.nextKey = nextKey
            self.version = 1
            self.serializedDatalog = try datalog.serializeInBiscuit(interner: &interner)
            self.externalSignature = try ExternalSignature(
                block: self.serializedDatalog,
                lastSig: lastSig,
                thirdPartyKey: thirdPartyKey,
            )
            self.signature = try lastKey.signature(
                for: SignatureV1.blockSignatureInput(
                    payload: self.serializedDatalog,
                    nextKey: self.nextKey,
                    prevSig: lastSig,
                    externalSig: self.externalSignature?.signature
                )
            )
        }

        init(
            contents: ThirdPartyBlockContents,
            nextKey: InternalPublicKey,
            lastKey: InternalPrivateKey,
            lastSig: Data
        ) throws {
            self.datalog = contents.payload
            self.serializedDatalog = contents.serializedPayload
            self.nextKey = nextKey
            self.externalSignature = contents.externalSignature
            self.version = 1
            self.signature = try lastKey.signature(
                for: SignatureV1.blockSignatureInput(
                    payload: self.serializedDatalog,
                    nextKey: self.nextKey,
                    prevSig: lastSig,
                    externalSig: self.externalSignature?.signature
                )
            )
        }

        static func authority<Key: PublicKey>(
            proto: Biscuit_Format_Schema_SignedBlock,
            key: Key,
            interner: inout InternmentTable
        ) throws -> Block {
            let block = try Block.unverifiedAuthority(proto: proto, interner: &interner)
            guard key.isValidSignature(block.signature, for: block.signatureInput()) else {
                throw ValidationError.invalidSignature
            }
            return block
        }

        static func attenuation(
            proto: Biscuit_Format_Schema_SignedBlock,
            lastBlock: Block,
            interner: inout InternmentTable
        ) throws -> Block {
            let block = try Block.unverifiedAttenuation(proto: proto, interner: &interner)
            if let externalSignature = block.externalSignature {
                try externalSignature.isValidSignature(for: block, lastSig: lastBlock.signature)
            }
            let signatureInput = block.signatureInput(lastSig: lastBlock.signature)
            guard lastBlock.nextKey.isValidSignature(block.signature, for: signatureInput) else {
                throw ValidationError.invalidSignature
            }
            return block
        }

        static func unverifiedAuthority(
            proto: Biscuit_Format_Schema_SignedBlock,
            interner: inout InternmentTable
        ) throws -> Block {
            try Self.checkProto(proto: proto)
            guard !proto.hasExternalSignature else {
                throw ValidationError.thirdPartySignedAuthority
            }
            return Block(
                datalog: try DatalogBlock(serializedData: proto.block, &interner),
                nextKey: try InternalPublicKey(proto: proto.nextKey),
                version: proto.hasVersion ? proto.version : nil,
                serializedDatalog: proto.block,
                signature: proto.signature,
                externalSignature: nil
            )
        }

        static func unverifiedAttenuation(
            proto: Biscuit_Format_Schema_SignedBlock,
            interner: inout InternmentTable
        ) throws -> Block {
            try Self.checkProto(proto: proto)
            let version = proto.hasVersion ? proto.version : nil
            if proto.hasExternalSignature {
                guard version ?? 0 >= 1 else {
                    throw ValidationError.deprecatedThirdPartySignature
                }
                var blockInterner = InternmentTable()
                return Block(
                    datalog: try DatalogBlock(serializedData: proto.block, &blockInterner),
                    nextKey: try InternalPublicKey(proto: proto.nextKey),
                    version: version,
                    serializedDatalog: proto.block,
                    signature: proto.signature,
                    externalSignature: try ExternalSignature(proto: proto.externalSignature)
                )
            } else {
                return Block(
                    datalog: try DatalogBlock(serializedData: proto.block, &interner),
                    nextKey: try InternalPublicKey(proto: proto.nextKey),
                    version: version,
                    serializedDatalog: proto.block,
                    signature: proto.signature,
                    externalSignature: nil
                )
            }
        }

        fileprivate init(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            version: UInt32?,
            serializedDatalog: Data,
            signature: Data,
            externalSignature: ExternalSignature?
        ) {
            self.datalog = datalog
            self.nextKey = nextKey
            self.version = version
            self.serializedDatalog = serializedDatalog
            self.signature = signature
            self.externalSignature = externalSignature
        }

        static func checkProto(proto: Biscuit_Format_Schema_SignedBlock) throws {
            guard proto.hasBlock else {
                throw ValidationError.missingBlockData
            }
            guard proto.hasSignature else {
                throw ValidationError.missingSignature
            }
            guard proto.hasNextKey else {
                throw ValidationError.missingPublicKey
            }
            if proto.hasVersion {
                guard proto.version <= 1 else {
                    throw ValidationError.invalidVersion
                }
            }
        }

        /// The revocation ID for this block
        public var revocationID: Data {
            self.signature
        }

        var proto: Biscuit_Format_Schema_SignedBlock {
            var proto = Biscuit_Format_Schema_SignedBlock()
            proto.signature = self.signature
            proto.nextKey = self.nextKey.proto
            if let version = self.version {
                proto.version = UInt32(version)
            }
            proto.block = self.serializedDatalog
            if let externalSignature = self.externalSignature {
                proto.externalSignature = externalSignature.proto
            }
            return proto
        }

        var signedByThirdParty: Bool { self.externalSignature != nil }

        /// The third party key that signed this block, if it exists
        public var thirdPartyKey: ThirdPartyKey? { self.externalSignature?.publicKey }

        func signatureInput(lastSig: Data? = nil) -> Data {
            switch self.version ?? 0 {
            case 0: return SignatureV0.blockSignatureInput(block: self)
            default: return SignatureV1.blockSignatureInput(block: self, sig: lastSig)
            }
        }

        func sealingSignatureInput() -> Data {
            SignatureV0.sealingSignatureInput(block: self)
        }

        struct ExternalSignature: Hashable {
            var signature: Data
            var publicKey: ThirdPartyKey

            init<Key: PrivateKey>(
                block: Data,
                lastSig: Data,
                thirdPartyKey: Key,
            ) throws {
                let input = SignatureV1.externalSignatureInput(block: block, sig: lastSig)
                self.signature = try thirdPartyKey.signature(for: input)
                self.publicKey = ThirdPartyKey(key: thirdPartyKey.publicKey)
            }

            init(proto: Biscuit_Format_Schema_ExternalSignature) throws {
                guard proto.hasSignature else {
                    throw ValidationError.missingSignature
                }
                guard proto.hasPublicKey else {
                    throw ValidationError.missingPublicKey
                }
                self.signature = proto.signature
                self.publicKey = ThirdPartyKey(proto: proto.publicKey)
            }

            func isValidSignature(for block: Block, lastSig: Data) throws {
                try self.publicKey.isValidExternalSignature(
                    self.signature,
                    for: block,
                    lastSig: lastSig,
                )
            }

            var proto: Biscuit_Format_Schema_ExternalSignature {
                var proto = Biscuit_Format_Schema_ExternalSignature()
                proto.signature = self.signature
                proto.publicKey = self.publicKey.proto
                return proto
            }
        }
    }
}
