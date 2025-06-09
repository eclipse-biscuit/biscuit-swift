/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

enum Token: Hashable {
    case date(Date)
    case bytes(Data)
    case name(Substring)
    case number(Int64)
    case publicKey(Biscuit.ThirdPartyKey)
    case string(Substring)
    case variable(Substring)
    case keyword(Keyword)
    // Punctuation:
    case ptBang, ptBangEq, ptBangEqEq, ptAmp, ptAmpAmp, ptParenL, ptParenR, ptStar, ptPlus, ptComma
    case ptHyphen, ptPeriod, ptSlash, ptSemicolon, ptColon, ptLt, ptLeftArrow, ptLtEq, ptEqEq
    case ptEqEqEq, ptGt, ptGtEq, ptBraceL, ptBraceR, ptBracketL, ptBracketR, ptCaret, ptBar
    case ptBarBar, ptRightArrow
}

enum Keyword: Hashable {
    case kwAll, kwAllow, kwAuthority, kwCheck, kwDeny, kwFalse, kwIf, kwOr, kwNull, kwPrevious
    case kwReject, kwTrue, kwTrusting

    var name: String {
        switch self {
            case .kwAll: "all"
            case .kwAllow: "allow"
            case .kwAuthority: "authority"
            case .kwCheck: "check"
            case .kwDeny: "deny"
            case .kwFalse: "false"
            case .kwIf: "if"
            case .kwOr: "or"
            case .kwNull: "null"
            case .kwPrevious: "previous"
            case .kwReject: "reject"
            case .kwTrue: "true"
            case .kwTrusting: "trusting"
        }
    }
}


struct Lexer {
    var input: Substring

    init(_ input: String) {
        self.input = input[...]
    }

    mutating func nextToken() throws -> Token? {
        var triviaMayContinue = true
        while triviaMayContinue {
            triviaMayContinue = false
            if let match = try? /\s+/.prefixMatch(in: self.input) {
                self.input = self.input[match.range.upperBound...]
                triviaMayContinue = true
            }
            if let match = try? /\/\/.*\n/.prefixMatch(in: self.input) {
                self.input = self.input[match.range.upperBound...]
                triviaMayContinue = true
            }
        }

        guard self.input.count > 0 else {
            return nil
        }

        let matches = regexes.compactMap { (regex, f) -> (_, _)? in
            if let match = try? regex.prefixMatch(in: self.input) {
                return (match, f)
            } else {
                return nil
            }
        }

        guard let (match, f) = matches.max(by: { $0.0.range.upperBound < $1.0.range.upperBound })
        else {
            throw Biscuit.DatalogError.errorInLexing
        }
        guard let token = try f(match.1) else {
            throw Biscuit.DatalogError.errorInLexing
        }
        self.input = self.input[match.range.upperBound...]
        return token
    }
}

let regexes: [(Regex, (Substring) throws -> Token?)] = [
    // punctuation:
    (/(!)/, { _ in .ptBang }),
    (/(!=)/, { _ in .ptBangEq }),
    (/(!==)/, { _ in .ptBangEqEq }),
    (/(&)/, { _ in .ptAmp }),
    (/(&&)/, { _ in .ptAmpAmp }),
    (/(\()/, { _ in .ptParenL }),
    (/(\))/, { _ in .ptParenR }),
    (/(\*)/, { _ in .ptStar }),
    (/(\+)/, { _ in .ptPlus }),
    (/(,)/, { _ in .ptComma }),
    (/(-)/, { _ in .ptHyphen }),
    (/(\.)/, { _ in .ptPeriod }),
    (/(\/)/, { _ in .ptSlash }),
    (/(;)/, { _ in .ptSemicolon }),
    (/(:)/, { _ in .ptColon }),
    (/(<)/, { _ in .ptLt }),
    (/(<=)/, { _ in .ptLtEq }),
    (/(==)/, { _ in .ptEqEq }),
    (/(===)/, { _ in .ptEqEqEq }),
    (/(>)/, { _ in .ptGt }),
    (/(>=)/, { _ in .ptGtEq }),
    (/(\{)/, { _ in .ptBraceL }),
    (/(\})/, { _ in .ptBraceR }),
    (/(\[)/, { _ in .ptBracketL }),
    (/(\])/, { _ in .ptBracketR }),
    (/(\^)/, { _ in .ptCaret }),
    (/(\|)/, { _ in .ptBar }),
    (/(\|\|)/, { _ in .ptBarBar }),
    (/(<-)/, { _ in .ptLeftArrow }),
    (/(->)/, { _ in .ptRightArrow }),

    // 2019-12-04T09:46:41Z
    (/(\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)/, { date($0) }),

    // name keyword or bytes:
    (/([:alpha:][\w:_]*)/, { nameKeywordOrBytes($0) }),

    // number:
    (/(-?\d+)/, { data in .number(Int64(data)!) }),

    // public key:
    (/ed25519\/([\da-f]+)/, { data in
        .publicKey(Biscuit.ThirdPartyKey(dataRepresentation: hexDecode(data)!, algorithm: .ed25519))
    }),
    (/secp256r1\/([\da-f]+)/, { data in
        .publicKey(Biscuit.ThirdPartyKey(dataRepresentation: hexDecode(data)!, algorithm: .secp256r1))
    }),

    // FIXME: don't support currently escaped quotation marks in strings
    // FIXME: don't currently unescape any other escape sequences (newlines, tabs, etc)
    // string:
    (/"([^"]*)"/, { data in .string(data) }),

    //variable:
    (/\$([\w:_]*)/, { data in .variable(data) }),
]

let keywords = [
    "all": Token.keyword(.kwAll),
    "allow": Token.keyword(.kwAllow),
    "authority": Token.keyword(.kwAuthority),
    "deny": Token.keyword(.kwDeny),
    "check": Token.keyword(.kwCheck),
    "false": Token.keyword(.kwFalse),
    "if": Token.keyword(.kwIf),
    "or": Token.keyword(.kwOr),
    "null": Token.keyword(.kwNull),
    "previous": Token.keyword(.kwPrevious),
    "reject": Token.keyword(.kwReject),
    "true": Token.keyword(.kwTrue),
    "trusting": Token.keyword(.kwTrusting),
]

func nameKeywordOrBytes(_ data: Substring) -> Token? {
    if let kw = keywords[String(data)] {
        return kw
    }

    if let match = try? /hex:([0-9a-fA-F]+)/.wholeMatch(in: data) {
        if let hex = hexDecode(match.1) {
            return .bytes(hex)
        } else {
            return nil
        }
    }

    return .name(data)
}

func hexDecode(_ string: Substring) -> Data? {
    if string.count % 2 != 0 || string.count == 0 {
        return nil
    }

    let stringBytes: Data = string.data(using: String.Encoding.utf8)!
    var bytes = Data()

    for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
        let char1 = stringBytes[i]
        let char2 = stringBytes[i + 1]

        bytes.append(htoi(char1)! << 4 + htoi(char2)!)
    }

    return bytes
}

func htoi(_ value: UInt8) -> UInt8? {
    let char0 = UInt8(UnicodeScalar("0").value)
    let charA = UInt8(UnicodeScalar("a").value)

    switch value {
        case char0...char0 + 9:
            return value - char0
        case charA...charA + 5:
            return value - charA + 10
        default:
            return nil
    }
}

func date(_ s: Substring) -> Token? {
    if let date = ISO8601DateFormatter().date(from: String(s)) {
        return .date(date)
    } else {
        return nil
    }
}
