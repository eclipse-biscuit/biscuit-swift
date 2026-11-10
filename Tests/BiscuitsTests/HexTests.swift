import Foundation
import XCTest

@testable import Biscuits

final class HexTests: XCTestCase {
    func testHexDecoding() {
        let cases: [(Data, String)] = [
            (Data(), ""),
            (Data([0x00]), "00"),
            (Data([0x12, 0xab]), "12ab"),
            (Data([0xff, 0x0f, 0xf0]), "ff0ff0"),
            (Data([0x12, 0xab]), "12AB"),
            (Data([0xab, 0xcd, 0xef]), "aBcDeF"),
        ]
        for (expected, input) in cases {
            XCTAssertEqual(hexDecode(input[...]), expected)
        }
    }

    func testInvalidHexDecoding() {
        for input in ["1", "123", "zz", "1g", "g1", "12 4", "0x12", "GG", "1G"] {
            XCTAssertNil(hexDecode(input[...]), "\(input) should not decode")
        }
    }

    func testInvalidHexStringThrows() {
        XCTAssertThrowsError(try Value.bytes(hexString: "zz")) { error in
            XCTAssertEqual(error as? Biscuit.DatalogError, Biscuit.DatalogError.invalidHexData)
        }
        XCTAssertThrowsError(try Biscuit.ThirdPartyKey(algorithm: .ed25519, hexString: "zz")) { error in
            XCTAssertEqual(error as? Biscuit.ValidationError, Biscuit.ValidationError.invalidHexData)
        }
    }

    func testEmptyHexString() throws {
        XCTAssertEqual(try Value.bytes(hexString: ""), Value(Data()))
        XCTAssertEqual(try Biscuit.ThirdPartyKey(algorithm: .ed25519, hexString: "").dataRepresentation, Data())
    }

    func testUppercaseHexString() throws {
        XCTAssertEqual(try Value.bytes(hexString: "12AB"), try Value.bytes(hexString: "12ab"))
        XCTAssertEqual(
            try Biscuit.ThirdPartyKey(algorithm: .ed25519, hexString: "ABCDEF"),
            try Biscuit.ThirdPartyKey(algorithm: .ed25519, hexString: "abcdef")
        )
    }

    #if DatalogParser
    func testParsingEmptyHex() throws {
        let fact = try Fact("f(hex:)")
        XCTAssertEqual(fact, Fact("f", Value(Data())))
        XCTAssertEqual(try Fact(fact.description), fact)
    }

    func testParsingUppercaseHex() throws {
        XCTAssertEqual(try Fact("f(hex:12AB)"), try Fact("f(hex:12ab)"))
        XCTAssertEqual(try TrustedScope("ed25519/ABCDEF"), try TrustedScope("ed25519/abcdef"))
        XCTAssertEqual(try TrustedScope("secp256r1/ABCDEF"), try TrustedScope("secp256r1/abcdef"))
    }

    func testParsingOddLengthHexThrows() {
        XCTAssertThrowsError(try Fact("f(hex:abc)")) { error in
            XCTAssertEqual(error as? Biscuit.DatalogError, Biscuit.DatalogError.errorInLexing)
        }
        for datalog in ["ed25519/abc", "secp256r1/abc"] {
            XCTAssertThrowsError(try TrustedScope(datalog)) { error in
                XCTAssertEqual(error as? Biscuit.DatalogError, Biscuit.DatalogError.errorInLexing)
            }
        }
    }
    #endif
}
