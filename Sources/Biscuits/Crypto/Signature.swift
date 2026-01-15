/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

struct SignatureV1 {
    fileprivate static let block: Data = Data("\0BLOCK\0".utf8)
    fileprivate static let external: Data = Data("\0EXTERNAL\0".utf8)

    fileprivate static let externalsig: Data = Data("\0EXTERNALSIG\0".utf8)
    fileprivate static let nextkey: Data = Data("\0NEXTKEY\0".utf8)
    fileprivate static let payload: Data = Data("\0PAYLOAD\0".utf8)
    fileprivate static let prevsig: Data = Data("\0PREVSIG\0".utf8)
    fileprivate static let version1: Data = Data("\0VERSION\0\u{1}\0\0\0".utf8)

    fileprivate static let ed25519: Data = Data("\0ALGORITHM\0\0\0\0\0".utf8)
    fileprivate static let secp256r1: Data = Data("\0ALGORITHM\0\u{1}\0\0\0".utf8)

    static func externalSignatureInput(block: Data, sig: Data) -> Data {
        var data = SignatureV1.external
        data.append(contentsOf: SignatureV1.version1)
        data.append(contentsOf: SignatureV1.payload)
        data.append(contentsOf: block)
        data.append(contentsOf: SignatureV1.prevsig)
        data.append(contentsOf: sig)
        return data
    }

    static func blockSignatureInput(block: Biscuit.Block, sig: Data?) -> Data {
        Self.blockSignatureInput(
            payload: block.serializedDatalog,
            nextKey: block.nextKey,
            prevSig: sig,
            externalSig: block.externalSignature?.signature
        )
    }

    static func blockSignatureInput(
        payload: Data,
        nextKey: Biscuit.InternalPublicKey,
        prevSig: Data?,
        externalSig: Data?
    ) -> Data {
        var data = SignatureV1.block
        data.append(contentsOf: SignatureV1.version1)
        data.append(contentsOf: SignatureV1.payload)
        data.append(contentsOf: payload)
        data.append(contentsOf: SignatureV1.algorithm(for: nextKey.algorithm))
        data.append(contentsOf: SignatureV1.nextkey)
        data.append(contentsOf: nextKey.dataRepresentation)
        if let sig = prevSig {
            data.append(contentsOf: SignatureV1.prevsig)
            data.append(contentsOf: sig)
        }
        if let sig = externalSig {
            data.append(contentsOf: SignatureV1.externalsig)
            data.append(contentsOf: sig)
        }
        return data
    }

    fileprivate static func algorithm(for algorithm: Biscuit.SigningAlgorithm) -> Data {
        switch algorithm.wrapped {
        case .ed25519: ed25519
        case .secp256r1: secp256r1
        }
    }
}

struct SignatureV0 {
    static func blockSignatureInput(block: Biscuit.Block) -> Data {
        var data = block.serializedDatalog
        if let externalSignature = block.externalSignature {
            data.append(contentsOf: externalSignature.signature)
        }
        data.append(contentsOf: algorithm(for: block.nextKey.algorithm))
        data.append(contentsOf: block.nextKey.dataRepresentation)
        return data
    }

    static func sealingSignatureInput(block: Biscuit.Block) -> Data {
        var data = block.serializedDatalog
        data.append(contentsOf: algorithm(for: block.nextKey.algorithm))
        data.append(contentsOf: block.nextKey.dataRepresentation)
        data.append(contentsOf: block.signature)
        return data
    }

    fileprivate static func algorithm(for algorithm: Biscuit.SigningAlgorithm) -> Data {
        switch algorithm.wrapped {
        case .ed25519: Data([0, 0, 0, 0])
        case .secp256r1: Data([1, 0, 0, 0])
        }
    }
}
