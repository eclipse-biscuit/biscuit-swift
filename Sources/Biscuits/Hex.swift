/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

func hexDecode(_ string: Substring) -> Data? {
    let utf8 = string.utf8
    guard utf8.count % 2 == 0 else {
        return nil
    }

    var bytes: [UInt8] = []
    bytes.reserveCapacity(utf8.count / 2)

    var iterator = utf8.makeIterator()
    while let char1 = iterator.next(), let char2 = iterator.next() {
        guard let high = htoi(char1), let low = htoi(char2) else {
            return nil
        }

        bytes.append(high << 4 + low)
    }

    return Data(bytes)
}

func htoi(_ value: UInt8) -> UInt8? {
    let char0 = UInt8(UnicodeScalar("0").value)
    let charA = UInt8(UnicodeScalar("a").value)
    let charUpperA = UInt8(UnicodeScalar("A").value)

    switch value {
    case char0...char0 + 9:
        return value - char0
    case charA...charA + 5:
        return value - charA + 10
    case charUpperA...charUpperA + 5:
        return value - charUpperA + 10
    default:
        return nil
    }
}
