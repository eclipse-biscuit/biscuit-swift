/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */

// This file handles base64url encoding because Swift historically only supported non-urlsafe
// base64. Swift 6.3 added support for encoding to urlsafe base64, but not decoding.

import Foundation

func base64URLEncoded(_ data: Data) -> String {
    #if compiler(>=6.3)
    if #available(macOS 26.4, iOS 26.4, tvOS 26.4, watchOS 26.4, visionOS 26.4, *) {
        return data.base64EncodedString(options: [.base64URLAlphabet, .omitPaddingCharacter])
    } else {
        return manualBase64URLEncoded(data)
    }
    #else
    return manualBase64URLEncoded(data)
    #endif
}

func base64URLDecoded(_ data: String) throws -> Data {
    try manualBase64URLDecoded(data)
}

private func manualBase64URLEncoded(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func manualBase64URLDecoded(_ data: String) throws -> Data {
    var base64Encoded =
        data
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    // Swift's base64 decoding requires padding bytes whereas base64url usually does not contain
    // padding bytes.
    if base64Encoded.count % 4 != 0 {
        base64Encoded += String(repeating: "=", count: 4 - (base64Encoded.count % 4))
    }
    guard let data = Data(base64Encoded: base64Encoded) else {
        throw Biscuit.ValidationError.invalidBase64URLString
    }

    return data
}
