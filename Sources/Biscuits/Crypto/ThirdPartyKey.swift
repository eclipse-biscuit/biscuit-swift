/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

extension Biscuit {
    /// A third party public key that has been used to sign a block
    public struct ThirdPartyKey: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The algorithm used by that key
        public let algorithm: SigningAlgorithm
        /// The binary representation of that key
        public let dataRepresentation: Data

        /// Construct a ThirdPartyKey from a conforming public key type
        public init<Key: PublicKey>(key: Key) {
            self.algorithm = key.algorithm
            self.dataRepresentation = key.dataRepresentation
        }

        public var description: String {
            "\(self.algorithm)/\(self.dataRepresentation.map { String(format: "%02hhx", $0) }.joined())"
        }

        public var debugDescription: String {
            self.description
        }
    
        init(dataRepresentation: Data, algorithm: SigningAlgorithm) {
            self.dataRepresentation = dataRepresentation
            self.algorithm = algorithm
        }

        init(proto: Biscuit_Format_Schema_PublicKey) {
            self.algorithm = SigningAlgorithm(algorithm: proto.algorithm)
            self.dataRepresentation = proto.key
        }

        var proto: Biscuit_Format_Schema_PublicKey {
            var proto = Biscuit_Format_Schema_PublicKey()
            proto.algorithm = self.algorithm.proto
            proto.key = self.dataRepresentation
            return proto
        }

        func isValidExternalSignature(_ signature: Data, for block: Block, lastSig: Data, interner: BlockInternmentTable) throws {
            let input = try SignatureV1.externalSignatureInput(block: block.datalog, sig: lastSig, interner: interner)
            switch self.algorithm.wrapped {
                case .ed25519: 
                    let key = try Curve25519.Signing.PublicKey(rawRepresentation: self.dataRepresentation)
                    guard key.isValidSignature(signature, for: input) else {
                        throw ValidationError.invalidExternalSignature
                    }
                case .secp256r1:
                    let key = try P256.Signing.PublicKey(compressedRepresentation: self.dataRepresentation)
                    guard key.isValidSignature(signature, for: input) else {
                        throw ValidationError.invalidExternalSignature
                    }
            }
        }
    }
}
