@preconcurrency import Crypto

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
    enum InternalPrivateKey: Sendable, Hashable {
        case ed25519(Curve25519.Signing.PrivateKey)
        case secp256r1(P256.Signing.PrivateKey)

        init(algorithm: SigningAlgorithm) {
            self =
                switch algorithm.wrapped {
                case .ed25519: .ed25519(Curve25519.Signing.PrivateKey())
                case .secp256r1: .secp256r1(P256.Signing.PrivateKey())
                }
        }

        init(rawRepresentation bytes: Data, algorithm: SigningAlgorithm) throws {
            self =
                switch algorithm.wrapped {
                case .ed25519: try .ed25519(Curve25519.Signing.PrivateKey(rawRepresentation: bytes))
                case .secp256r1: try .secp256r1(P256.Signing.PrivateKey(rawRepresentation: bytes))
                }
        }

        func signature(for input: Data) throws -> Data {
            switch self {
            case .ed25519(let key): try key.signature(for: input)
            case .secp256r1(let key): try key.signature(for: input)
            }
        }

        func sealingSignature(for block: Block, interner: BlockInternmentTable) throws -> Data {
            try self.signature(for: block.sealingSignatureInput(interner: interner))
        }

        static func == (lhs: InternalPrivateKey, rhs: InternalPrivateKey) -> Bool {
            lhs.algorithm == rhs.algorithm && lhs.dataRepresentation == rhs.dataRepresentation
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(self.algorithm)
            hasher.combine(self.dataRepresentation)
        }

        var algorithm: SigningAlgorithm {
            switch self {
            case .ed25519: .ed25519
            case .secp256r1: .secp256r1
            }
        }

        var publicKey: InternalPublicKey {
            switch self {
            case .ed25519(let key): .ed25519(key.publicKey)
            case .secp256r1(let key): .secp256r1(key.publicKey)
            }
        }

        var dataRepresentation: Data {
            switch self {
            case .ed25519(let key): key.rawRepresentation
            case .secp256r1(let key): key.rawRepresentation
            }
        }
    }

    enum InternalPublicKey: Sendable, Hashable, PublicKey {
        case ed25519(Curve25519.Signing.PublicKey)
        case secp256r1(P256.Signing.PublicKey)

        init<Key: PublicKey>(_ key: Key) throws {
            self =
                switch key.algorithm.wrapped {
                case .ed25519: try .ed25519(Curve25519.Signing.PublicKey(rawRepresentation: key.dataRepresentation))
                case .secp256r1:
                    try .secp256r1(P256.Signing.PublicKey(compressedRepresentation: key.dataRepresentation))
                }
        }

        init(proto: Biscuit_Format_Schema_PublicKey) throws {
            self =
                switch proto.algorithm {
                case .ed25519: try .ed25519(Curve25519.Signing.PublicKey(rawRepresentation: proto.key))
                case .secp256R1: try .secp256r1(P256.Signing.PublicKey(compressedRepresentation: proto.key))
                }
        }

        init(rawRepresentation bytes: Data, algorithm: SigningAlgorithm = .ed25519) throws {
            self =
                switch algorithm.wrapped {
                case .ed25519: try .ed25519(Curve25519.Signing.PublicKey(rawRepresentation: bytes))
                case .secp256r1: try .secp256r1(P256.Signing.PublicKey(compressedRepresentation: bytes))
                }
        }

        static func == (lhs: InternalPublicKey, rhs: InternalPublicKey) -> Bool {
            lhs.algorithm == rhs.algorithm && lhs.dataRepresentation == rhs.dataRepresentation
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(self.algorithm)
            hasher.combine(self.dataRepresentation)
        }

        func isValidSignature(_ signature: Data, for input: Data) -> Bool {
            switch self {
            case .ed25519(let key):
                return key.isValidSignature(signature, for: input)
            case .secp256r1(let key):
                guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
                else {
                    return false
                }
                return key.isValidSignature(signature, for: input)
            }
        }

        func isValidSignature(for block: Block, interner: BlockInternmentTable) throws {
            guard try self.isValidSignature(block.signature, for: block.signatureInput(interner: interner)) else {
                throw ValidationError.invalidSignature
            }
        }

        func isValidSealingSignature(_ signature: Data, for block: Block, interner: BlockInternmentTable) throws {
            guard try self.isValidSignature(signature, for: block.sealingSignatureInput(interner: interner)) else {
                throw ValidationError.invalidSealingSignature
            }
        }

        var algorithm: SigningAlgorithm {
            switch self {
            case .ed25519: .ed25519
            case .secp256r1: .secp256r1
            }
        }

        var dataRepresentation: Data {
            switch self {
            case .ed25519(let key): key.rawRepresentation
            case .secp256r1(let key): key.compressedRepresentation
            }
        }

        var proto: Biscuit_Format_Schema_PublicKey {
            var proto = Biscuit_Format_Schema_PublicKey()
            proto.algorithm = self.algorithm.proto
            proto.key = self.dataRepresentation
            return proto
        }
    }
}
