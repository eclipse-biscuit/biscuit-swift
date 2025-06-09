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
    /// A private key that can be used to sign a biscuit
    public protocol PrivateKey {
        /// The public key type associated with this private key type
        associatedtype PublicKey: Biscuit.PublicKey
        /// Produce a cryptographic signature
        /// - Parameters:
        ///   - for: the data to be signed
        func signature(for input: Data) throws -> Data
        /// The public key associated with this private key
        var publicKey: PublicKey { get }
    }

    /// A public key that can be used to validate a signature on a biscuit
    public protocol PublicKey: TrustedScopeConvertible {
        /// Validate a cryptographic signature
        /// - Parameters:
        ///   - signature: the signature to be validated
        ///   - for: the data signed with that signature
        func isValidSignature(_ signature: Data, for input: Data) -> Bool
        /// Which algorithm this key uses
        var algorithm: SigningAlgorithm { get }
        /// This key represented as Data
        var dataRepresentation: Data { get }
    }
}

extension Curve25519.Signing.PrivateKey: Biscuit.PrivateKey { }

extension P256.Signing.PrivateKey: Biscuit.PrivateKey {
    public func signature(for input: Data) throws -> Data {
        try self.signature(for: input).rawRepresentation
    }
}

extension SecureEnclave.P256.Signing.PrivateKey: Biscuit.PrivateKey {
    public func signature(for input: Data) throws -> Data {
        try self.signature(for: input).rawRepresentation
    }
}

extension Curve25519.Signing.PublicKey: Biscuit.PublicKey {
    public var algorithm: Biscuit.SigningAlgorithm { .ed25519 }
    public var dataRepresentation: Data { self.rawRepresentation }
}

extension P256.Signing.PublicKey: Biscuit.PublicKey {
    public func isValidSignature(_ signature: Data, for input: Data) -> Bool {
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        else {
            return false
        }
        return self.isValidSignature(signature, for: input)
    }

    public var algorithm: Biscuit.SigningAlgorithm { .secp256r1 }
    public var dataRepresentation: Data { self.compressedRepresentation }
}
