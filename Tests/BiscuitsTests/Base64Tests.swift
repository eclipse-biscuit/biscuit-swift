import Foundation
import XCTest

@testable import Biscuits

final class Base64Tests: XCTestCase {
    func testBase64UrlEncoding() {
        let cases: [(Data, String)] = [
            (Data([]), ""),
            (Data([0x66]), "Zg"),
            (Data([0x66, 0x6f, 0x6f]), "Zm9v"),
            (Data([0xfb]), "-w"),
            (Data([0xff]), "_w"),
            (Data([0xfb, 0xff, 0xfe]), "-__-"),
            (Data([0x00, 0x00, 0x00]), "AAAA"),
            (Data("Hello, World!".utf8), "SGVsbG8sIFdvcmxkIQ"),
        ]
        for (input, expected) in cases {
            XCTAssertEqual(base64URLEncoded(input), expected)
        }
    }

    func testBase64UrlDecoding() {
        let cases: [(Data, String)] = [
            (Data([]), ""),
            (Data([0x66]), "Zg"),
            (Data([0x66, 0x6f, 0x6f]), "Zm9v"),
            (Data([0xfb]), "-w"),
            (Data([0xff]), "_w"),
            (Data([0xfb, 0xff, 0xfe]), "-__-"),
            (Data([0x00, 0x00, 0x00]), "AAAA"),
            (Data("Hello, World!".utf8), "SGVsbG8sIFdvcmxkIQ"),
        ]
        for (expected, input) in cases {
            try XCTAssertEqual(base64URLDecoded(input), expected)
        }
    }
}
