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
    enum Proof: Sendable, Hashable {
        case nextSecret(InternalPrivateKey)
        case finalSignature(Data)

        init(proto: Biscuit_Format_Schema_Proof, algorithm: SigningAlgorithm) throws {
            switch proto.content {
            case .nextSecret(let key):
                self = try .nextSecret(InternalPrivateKey(rawRepresentation: key, algorithm: algorithm))
            case .finalSignature(let signature):
                self = .finalSignature(signature)
            case .none:
                throw ValidationError.missingProof
            }
        }

        func isValidProof(for block: Block, interner: BlockInternmentTable) throws {
            switch self {
            case .finalSignature(let sig):
                try block.nextKey.isValidSealingSignature(sig, for: block, interner: interner)
            case .nextSecret(let nextKey):
                guard block.nextKey == nextKey.publicKey else {
                    throw ValidationError.invalidProof
                }
            }
        }

        var proto: Biscuit_Format_Schema_Proof {
            var proto = Biscuit_Format_Schema_Proof()
            switch self {
            case .nextSecret(let key):
                proto.nextSecret = key.dataRepresentation
            case .finalSignature(let sig):
                proto.finalSignature = sig
            }
            return proto
        }

        var isSealed: Bool {
            switch self {
            case .nextSecret(_): false
            case .finalSignature(_): true
            }
        }
    }
}
