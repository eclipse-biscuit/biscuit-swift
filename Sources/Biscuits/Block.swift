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
        var signature: Data
        var externalSignature: ExternalSignature?

        init<Key: PrivateKey>(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            key: Key,
            interner: BlockInternmentTable
        ) throws {
            self.datalog = datalog
            self.nextKey = nextKey
            self.version = 1
            self.signature = Data()
            self.signature = try key.signature(for: self.signatureInput(interner: interner))
        }

        init(
            datalog: DatalogBlock,
            nextKey: InternalPublicKey,
            lastKey: InternalPrivateKey,
            lastSig: Data,
            externalSignature: ExternalSignature?,
            interner: BlockInternmentTable
        ) throws {
            self.datalog = datalog
            self.nextKey = nextKey
            self.externalSignature = externalSignature
            self.version = 1
            self.signature = Data()
            let signatureInput = try self.signatureInput(interner: interner, lastSig: lastSig)
            self.signature = try lastKey.signature(for: signatureInput)
        }

        // for the authority block
        init<Key: PublicKey>(proto: Biscuit_Format_Schema_SignedBlock, key: Key, interner: inout InternmentTables) throws {
            self = try Block.init(proto: proto, interner: &interner)
            let signatureInput = try self.signatureInput(interner: interner.primary)
            guard key.isValidSignature(self.signature, for: signatureInput) else {
                throw ValidationError.invalidSignature
            }
        }

        // for attenuation blocks
        init(proto: Biscuit_Format_Schema_SignedBlock, lastBlock: Block, blockID: Int, interner: inout InternmentTables) throws {
            self = try Block.init(proto: proto, blockID: blockID, interner: &interner)
            let blockInterner = interner.blockTable(for: blockID)
            let signatureInput = try self.signatureInput(interner: blockInterner, lastSig: lastBlock.signature)
            guard lastBlock.nextKey.isValidSignature(self.signature, for: signatureInput) else {
                throw ValidationError.invalidSignature
            }
            if let externalSignature = self.externalSignature {
                try externalSignature.isValidSignature(for: self, lastSig: lastBlock.signature, interner: blockInterner)
            }
        }

        init(proto: Biscuit_Format_Schema_SignedBlock, interner: inout InternmentTables) throws {
            try Self.checkProto(proto: proto)
            guard !proto.hasExternalSignature else {
                throw ValidationError.thirdPartySignedAuthority
            }
            self.nextKey = try InternalPublicKey(proto: proto.nextKey)
            self.version = proto.hasVersion ? proto.version : nil
            self.signature = proto.signature
            self.datalog = try DatalogBlock(serializedData: proto.block, &interner.primary)
        }
        
        init(proto: Biscuit_Format_Schema_SignedBlock, blockID: Int, interner: inout InternmentTables) throws {
            try Self.checkProto(proto: proto)
            self.nextKey = try InternalPublicKey(proto: proto.nextKey)
            self.version = proto.hasVersion ? proto.version : nil
            self.signature = proto.signature
            if proto.hasExternalSignature {
                guard self.version ?? 0 >= 1 else {
                    throw ValidationError.deprecatedThirdPartySignature
                }
                var blockInterner = BlockInternmentTable()
                self.datalog = try DatalogBlock(serializedData: proto.block, &blockInterner)
                let externalSignature = try ExternalSignature(proto: proto.externalSignature)
                self.externalSignature = externalSignature
                interner.setBlockTable(blockInterner, for: blockID)
            } else {
                self.datalog = try DatalogBlock(serializedData: proto.block, &interner.primary)
            }
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

        func proto(interner: BlockInternmentTable) throws -> Biscuit_Format_Schema_SignedBlock {
            var proto = Biscuit_Format_Schema_SignedBlock()
            proto.signature = self.signature
            proto.nextKey = self.nextKey.proto
            if let version = self.version {
                proto.version = UInt32(version)
            }
            proto.block = try self.datalog.serializedData(interner)
            if let externalSignature = self.externalSignature {
                proto.externalSignature = externalSignature.proto
            }
            return proto
        }

        var signedByThirdParty: Bool { self.externalSignature != nil }
        
        /// The third party key that signed this block, if it exists
        public var thirdPartyKey: ThirdPartyKey? { self.externalSignature?.publicKey }

        func signatureInput(interner: BlockInternmentTable, lastSig: Data? = nil) throws -> Data {
            switch self.version ?? 0 {
                case 0: return try SignatureV0.blockSignatureInput(block: self, interner: interner)
                default: return try SignatureV1.blockSignatureInput(block: self, sig: lastSig, interner: interner)
            }
        }

        func sealingSignatureInput(interner: BlockInternmentTable) throws -> Data {
            try SignatureV0.sealingSignatureInput(block: self, interner: interner)
        }

        struct ExternalSignature: Hashable {
            var signature: Data
            var publicKey: ThirdPartyKey

            init<Key: PrivateKey>(
                block: DatalogBlock,
                lastSig: Data,
                thirdPartyKey: Key,
                interner: BlockInternmentTable
            ) throws {
                let input = try SignatureV1.externalSignatureInput(block: block, sig: lastSig, interner: interner)
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

            func isValidSignature(for block: Block, lastSig: Data, interner: BlockInternmentTable) throws {
                try self.publicKey.isValidExternalSignature(self.signature, for: block, lastSig: lastSig, interner: interner)
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
