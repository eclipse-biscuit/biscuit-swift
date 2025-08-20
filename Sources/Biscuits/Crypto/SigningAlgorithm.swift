/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// A signing algorithm supported by biscuits
    public struct SigningAlgorithm: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
        internal enum Wrapped: Hashable {
            case ed25519, secp256r1
        }

        internal let wrapped: Wrapped

        init(_ wrapped: Wrapped) {
            self.wrapped = wrapped
        }

        init(algorithm: Biscuit_Format_Schema_PublicKey.Algorithm) {
            self =
                switch algorithm {
                case .ed25519: .ed25519
                case .secp256R1: .secp256r1
                }
        }

        /// The ED25519 signing algorithm
        public static var ed25519: SigningAlgorithm { SigningAlgorithm(.ed25519) }
        /// The ECDSA P256 signing algorithm
        public static var secp256r1: SigningAlgorithm { SigningAlgorithm(.secp256r1) }

        public var description: String {
            switch self.wrapped {
            case .ed25519: "ed25519"
            case .secp256r1: "secp256r1"
            }
        }

        public var debugDescription: String {
            self.description
        }

        var proto: Biscuit_Format_Schema_PublicKey.Algorithm {
            switch self.wrapped {
            case .ed25519: .ed25519
            case .secp256r1: .secp256R1
            }
        }
    }
}
