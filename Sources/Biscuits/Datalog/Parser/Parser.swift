/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
struct Parser {
    var lexer: Lexer
    var currentToken: Token?
    var symbols: [String] = []
    var publicKeys: [Biscuit.ThirdPartyKey] = []
    var origins: [TrustedScope] = []
    var policies: [Policy] = []
    var checks: [Check] = []
    var rules: [Rule] = []
    var facts: [Fact] = []

    init(_ input: String) {
        self.lexer = Lexer(input)
    }

    static func forAuthorizer(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        try parser.parseBlockScopes()
        while let token = try parser.eat() {
            switch token {
            case .keyword(.kwAllow): try parser.parsePolicy(true)
            case .keyword(.kwDeny): try parser.parsePolicy(false)
            case .keyword(.kwCheck): try parser.parseCheck()
            case .keyword(.kwReject): try parser.parseReject()
            case .keyword(let kw): try parser.parseFactOrRule(kw.name[...])
            case .name(let name): try parser.parseFactOrRule(name)
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        }
        return parser
    }

    static func forDatalogBlock(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        try parser.parseBlockScopes()
        while let token = try parser.eat() {
            switch token {
            case .keyword(.kwCheck): try parser.parseCheck()
            case .keyword(.kwReject): try parser.parseReject()
            case .keyword(let kw): try parser.parseFactOrRule(kw.name[...])
            case .name(let name): try parser.parseFactOrRule(name)
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        }
        return parser
    }

    static func forPolicy(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        switch try parser.eat() {
        case .keyword(.kwAllow): try parser.parseCheck()
        case .keyword(.kwDeny): try parser.parseReject()
        case .none: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownBlockElement(token!)
        }
        return parser
    }

    static func forQuery(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        if let token = try parser.eat() {
            switch token {
            case .keyword(.kwCheck): try parser.parseCheck()
            case .keyword(.kwReject): try parser.parseReject()
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        } else {
            throw Biscuit.DatalogError.unexpectedEndOfCode
        }
        return parser
    }

    static func forRule(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        if let token = try parser.eat() {
            switch token {
            case .name(let name):
                var headVars: Set<String> = []
                let head = try parser.parsePredicate(name, { headVars.insert($0);  })
                guard case .ptLeftArrow = try parser.eat() else {
                    throw Biscuit.DatalogError.unexpectedEndOfCode
                }
                try parser.rules.append(parser.parseRule(head, { headVars.remove($0) }))
                guard headVars.isEmpty else {
                    throw Biscuit.DatalogError.variableInHeadAlone
                }
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        } else {
            throw Biscuit.DatalogError.unexpectedEndOfCode
        }
        return parser
    }

    static func predicate(using datalog: String) throws -> Predicate {
        var parser = Parser(datalog)
        if let token = try parser.eat() {
            switch token {
            case .name(let name):
                let predicate = try parser.parsePredicate(name) { _ in () }
                return predicate
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        } else {
            throw Biscuit.DatalogError.unexpectedEndOfCode
        }
    }

    static func forFact(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        if let token = try parser.eat() {
            switch token {
            case .name(let name):
                let predicate = try parser.parsePredicate(name) { _ in () }
                try parser.facts.append(predicate.forceConcrete())
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        } else {
            throw Biscuit.DatalogError.unexpectedEndOfCode
        }
        return parser
    }

    static func forTrusting(using datalog: String) throws -> Parser {
        var parser = Parser(datalog)
        if let token = try parser.eat() {
            switch token {
            case .keyword(.kwTrusting): parser.origins = try parser.parseScopes()
            default: throw Biscuit.DatalogError.unknownBlockElement(token)
            }
        } else {
            throw Biscuit.DatalogError.unexpectedEndOfCode
        }
        return parser
    }

    mutating func parseBlockScopes() throws {
        if case .keyword(.kwTrusting) = try self.at() {
            self.bump()
            self.origins = try self.parseScopes()
            guard case .ptSemicolon = try self.eat() else {
                throw Biscuit.DatalogError.missingSemicolon
            }
        }
    }

    mutating func parseScopes() throws -> [TrustedScope] {
        var origins: [TrustedScope] = []
        try origins.append(self.parseScope())
        while true {
            if case .ptComma = try self.at() {
                self.bump()
                try origins.append(self.parseScope())
            } else {
                return origins
            }
        }
    }

    mutating func parseScope() throws -> TrustedScope {
        switch try self.eat() {
        case .keyword(.kwAuthority): return .authority
        case .keyword(.kwPrevious): return .previous
        case .publicKey(let key): return TrustedScope(.publicKey(key))
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownScope(token!)
        }
    }

    mutating func parsePolicy(_ allow: Bool) throws {
        switch try self.eat() {
        case .keyword(.kwIf): break
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownPolicy(token!)
        }
        var queries: [Biscuit.Query] = []
        while true {
            try queries.append(self.parseQuery({ _ in () }))
            switch try self.eat() {
            case .keyword(.kwOr): break
            case .ptSemicolon:
                if allow {
                    self.policies.append(Policy(queries, .allowIf))
                } else {
                    self.policies.append(Policy(queries, .denyIf))
                }
                return
            default: throw Biscuit.DatalogError.missingSemicolon
            }
        }
    }

    mutating func parseCheck() throws {
        var queries: [Biscuit.Query] = []
        switch try self.eat() {
        case .keyword(.kwIf):
            while true {
                try queries.append(self.parseQuery({ _ in () }))
                switch try self.eat() {
                case .keyword(.kwOr): break
                case .ptSemicolon:
                    self.checks.append(Check(.checkIf, queries))
                    return
                default: throw Biscuit.DatalogError.missingSemicolon
                }
            }
        case .keyword(.kwAll):
            while true {
                try queries.append(self.parseQuery({ _ in () }))
                switch try self.eat() {
                case .keyword(.kwOr): break
                case .ptSemicolon:
                    self.checks.append(Check(.checkAll, queries))
                    return
                default: throw Biscuit.DatalogError.missingSemicolon
                }
            }
        case nil:
            throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownCheck(token!)
        }
    }

    mutating func parseReject() throws {
        var queries: [Biscuit.Query] = []
        switch try self.eat() {
        case .keyword(.kwIf):
            while true {
                try queries.append(self.parseQuery({ _ in () }))
                switch try self.eat() {
                case .keyword(.kwOr): break
                case .ptSemicolon:
                    self.checks.append(Check(.rejectIf, queries))
                    return
                default: throw Biscuit.DatalogError.missingSemicolon
                }
            }
        case nil:
            throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownCheck(token!)
        }
    }

    mutating func parseFactOrRule(_ name: Substring) throws {
        var headVars: Set<String> = []
        let head = try self.parsePredicate(name, { headVars.insert($0);  })
        switch try self.eat() {
        case .ptLeftArrow:
            try self.rules.append(self.parseRule(head, { headVars.remove($0);  }))
            guard case .ptSemicolon = try self.eat() else {
                throw Biscuit.DatalogError.missingSemicolon
            }
            guard headVars.isEmpty else {
                throw Biscuit.DatalogError.variableInHeadAlone
            }
        case .ptSemicolon:
            try self.facts.append(head.forceConcrete())
        default: throw Biscuit.DatalogError.missingSemicolon
        }
    }

    mutating func parseQuery(_ f: (String) -> Void) throws -> Biscuit.Query {
        var predicates: [Predicate] = []
        var expressions: [Biscuits.Expression] = []
        var origins: [TrustedScope] = []
        try self.parsePredicateOrExpression(
            &predicates,
            &expressions,
            f
        )
        while true {
            switch try self.at() {
            case .ptComma:
                self.bump()
                try self.parsePredicateOrExpression(
                    &predicates,
                    &expressions,
                    f
                )
            case .keyword(.kwTrusting):
                self.bump()
                origins = try self.parseScopes()
                return Biscuit.Query(predicates, expressions, origins)
            default:
                return Biscuit.Query(predicates, expressions, origins)
            }
        }
    }

    mutating func parseRule(_ head: Predicate, _ f: (String) -> Void) throws -> Rule {
        var predicates: [Predicate] = []
        var expressions: [Biscuits.Expression] = []
        var origins: [TrustedScope] = []
        try self.parsePredicateOrExpression(
            &predicates,
            &expressions,
            f
        )
        while true {
            switch try self.at() {
            case .ptComma:
                self.bump()
                try self.parsePredicateOrExpression(
                    &predicates,
                    &expressions,
                    f
                )
            case .keyword(.kwTrusting):
                self.bump()
                origins = try self.parseScopes()
                return Rule(head, predicates, expressions, origins)
            default:
                return Rule(head, predicates, expressions, origins)
            }
        }
    }

    mutating func parsePredicateOrExpression(
        _ predicates: inout [Predicate],
        _ expressions: inout [Biscuits.Expression],
        _ f: (String) -> Void
    ) throws {
        switch try self.at() {
        case .keyword(let kw):
            self.bump()
            let potentialValue: Value? =
                switch kw {
                case .kwTrue: Value(true)
                case .kwFalse: Value(false)
                case .kwNull: Value.null
                default: nil
                }
            if case .ptParenL = try self.at() {
                try predicates.append(self.parsePredicate(kw.name[...], f))
            } else if let value = potentialValue {
                let expression = try self.parseExpression(f, 0, Expression.term(Term(value: value)))
                expressions.append(Biscuits.Expression(parse: expression))
            }
        case .name(let name):
            self.bump()
            try predicates.append(self.parsePredicate(name, f))
        default:
            try expressions.append(Biscuits.Expression(parse: self.parseExpression(f)))
        }
    }

    mutating func parsePredicate(_ name: Substring, _ f: (String) -> Void) throws -> Predicate {
        let name = String(name)
        switch try self.eat() {
        case .ptParenL: break
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownPredicate(token!)
        }
        var terms: [Term] = []
        if case .ptParenR = try self.at() {
            return Predicate(name, terms)
        }
        try terms.append(self.parseTerm(f))
        while true {
            switch try self.eat() {
            case .ptComma: try terms.append(self.parseTerm(f))
            case .ptParenR: return Predicate(name, terms)
            case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
            case let token: throw Biscuit.DatalogError.unknownPredicate(token!)
            }
        }
    }

    mutating func parseExpression(
        _ f: (String) -> Void,
        _ precedence: Int = 0,
        _ lhs: Expression? = nil
    ) throws -> Expression {
        var lhs = try self.parseExpressionPrefix(f, lhs)
        while let op = try self.parseBinaryOp() {
            if op.precedence <= precedence {
                guard op.leftAssociative || op.precedence < precedence else {
                    throw Biscuit.DatalogError.chainedComparisonsWithoutParens
                }
                return lhs
            }
            self.bump()
            var rhs = try self.parseExpression(f, op.precedence)
            if op == .lazyAnd || op == .lazyOr {
                rhs = .closure(Closure(params: [], body: rhs))
            }
            lhs = .binaryOp(op, lhs, rhs)
        }
        return lhs
    }

    mutating func parseExpressionPrefix(_ f: (String) -> Void, _ lhs: Expression? = nil) throws -> Expression {
        if let lhs = lhs {
            return try self.parseExpressionMethod(f, lhs)
        }
        switch try self.at() {
        case .ptBang:
            self.bump()
            return try .unaryOp(.negate, self.parseExpressionPrefix(f))
        case .ptParenL:
            self.bump()
            let expr = try self.parseExpression(f)
            guard case .ptParenR = try self.eat() else {
                throw Biscuit.DatalogError.missingRightParen
            }
            return try self.parseExpressionMethod(f, .unaryOp(.parens, expr))
        default: return try self.parseExpressionMethod(f)
        }
    }

    mutating func parseExpressionMethod(_ f: (String) -> Void, _ lhs: Expression? = nil) throws -> Expression {
        func methodErr(_ token: Token?) -> Biscuit.DatalogError {
            if let token = token {
                return Biscuit.DatalogError.unknownMethod(token)
            } else {
                return Biscuit.DatalogError.unexpectedEndOfCode
            }
        }
        enum MethodType {
            case unary(OpUnary)
            case binary(OpBinary)
            case closure(OpBinary)
            case tryOr
        }

        var expr: Expression = try lhs ?? .term(self.parseTerm(f))
        while case .ptPeriod = try self.at() {
            self.bump()
            let name: Substring =
                switch try self.eat() {
                case .name(let n): n
                case .keyword(.kwAll): "all"
                case let token: throw methodErr(token)
                }
            switch try self.eat() {
            case .ptParenL: break
            case let token: throw methodErr(token)
            }
            let methodType: MethodType =
                switch name {
                case "all": .closure(.all)
                case "any": .closure(.any)
                case "contains": .binary(.contains)
                case "ends_with": .binary(.endsWith)
                case "get": .binary(.get)
                case "intersection": .binary(.intersection)
                case "length": .unary(.length)
                case "matches": .binary(.regex)
                case "starts_with": .binary(.startsWith)
                case "try_or": .tryOr
                case "type": .unary(.typeOf)
                case "union": .binary(.union)
                default: throw Biscuit.DatalogError.unknownMethod(.name(name))
                }
            switch methodType {
            case .unary(let op):
                switch try self.eat() {
                case .ptParenR: break
                case let token: throw methodErr(token)
                }
                expr = .unaryOp(op, expr)
            case .binary(let op):
                let arg = try self.parseExpression(f)
                switch try self.eat() {
                case .ptParenR: expr = .binaryOp(op, expr, arg)
                case let token: throw methodErr(token)
                }
            case .closure(let op):
                let arg = try self.parseClosure(f)
                switch try self.eat() {
                case .ptParenR: expr = .binaryOp(op, expr, .closure(arg))
                case let token: throw methodErr(token)
                }
            case .tryOr:
                let arg = try self.parseExpression(f)
                let receiver = Closure(params: [], body: expr)
                switch try self.eat() {
                case .ptParenR: expr = .binaryOp(.tryOr, .closure(receiver), arg)
                case let token: throw methodErr(token)
                }
            }
        }
        return expr
    }

    mutating func parseBinaryOp() throws -> OpBinary? {
        switch try self.at() {
        case .ptBangEq: .heterogeneousNotEqual
        case .ptBangEqEq: .notEq
        case .ptAmp: .bitwiseAnd
        case .ptAmpAmp: .lazyAnd
        case .ptStar: .mul
        case .ptPlus: .add
        case .ptHyphen: .sub
        case .ptSlash: .div
        case .ptLt: .lt
        case .ptLtEq: .ltEq
        case .ptEqEq: .heterogeneousEqual
        case .ptEqEqEq: .eq
        case .ptGt: .gt
        case .ptGtEq: .gtEq
        case .ptCaret: .bitwiseXor
        case .ptBar: .bitwiseOr
        case .ptBarBar: .lazyOr
        default: nil
        }
    }

    mutating func parseClosure(_ f: (String) -> Void) throws -> Closure {
        let params = try self.parseClosureParams()
        let body = try self.parseExpression(f)
        return Closure(params: params, body: body)
    }

    mutating func parseClosureParams() throws -> [String] {
        var params: [String] = []
        while let param = try self.parseClosureParam() {
            params.append(param)
            switch try self.eat() {
            case .ptComma: continue
            case .ptRightArrow: return params
            case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
            case let token: throw Biscuit.DatalogError.unknownTerm(token!)
            }
        }
        return params
    }

    mutating func parseClosureParam() throws -> String? {
        switch try self.eat() {
        case .variable(let v): return String(v)
        case .ptRightArrow: return nil
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownTerm(token!)
        }
    }

    mutating func parseTerm(_ f: (String) -> Void) throws -> Term {
        switch try self.eat() {
        case .ptBraceL: return try Term(value: self.parseSetOrMap())
        case .ptBracketL: return try Term(value: self.parseArray())
        case .keyword(.kwTrue): return Term(value: true)
        case .keyword(.kwFalse): return Term(value: false)
        case .keyword(.kwNull): return Term(value: Value.null)
        case .bytes(let data): return Term(value: data)
        case .date(let date): return Term(value: date)
        case .number(let n): return Term(value: Value(.integer(n)))
        case .string(let string): return Term(value: String(string))
        case .variable(let variable):
            let v = String(variable)
            f(v)
            return Term(variable: v)
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownTerm(token!)
        }
    }

    mutating func parseSetOrMap() throws -> Value {
        let firstValue: Value
        switch try self.eat() {
        case .keyword(.kwTrue): firstValue = Value(true)
        case .keyword(.kwFalse): firstValue = Value(false)
        case .keyword(.kwNull): firstValue = Value.null
        case .bytes(let data): firstValue = Value(data)
        case .date(let date): firstValue = Value(date)
        case .number(let n): firstValue = Value(.integer(n))
        case .string(let string): firstValue = Value(String(string))
        case .ptBraceL: firstValue = try self.parseSetOrMap()
        case .ptBracketL: firstValue = try self.parseArray()
        case .ptBraceR: return Value.emptyMap
        case .ptComma:
            switch try self.eat() {
            case .ptBraceR: return Value.emptySet
            case let token: throw Biscuit.DatalogError.unknownTerm(token!)
            }
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownTerm(token!)
        }
        switch try self.eat() {
        case .ptComma: return try self.parseSet(first: firstValue)
        case .ptColon: return try self.parseMap(first: firstValue)
        case .ptBraceR:
            return try Value.set(from: [firstValue])
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token: throw Biscuit.DatalogError.unknownTerm(token!)
        }
    }

    mutating func parseSet(first: Value) throws -> Value {
        var elems: Set<Value> = [first]
        while let value = try self.parseValue(terminal: .ptBraceR) {
            elems.insert(value)
            switch try self.eat() {
            case .ptComma: continue
            case .ptBraceR: return try Value.set(from: elems)
            case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
            case let token: throw Biscuit.DatalogError.unknownTerm(token!)
            }
        }
        return try Value.set(from: elems)
    }

    mutating func parseMap(first: Value) throws -> Value {
        let firstKey: MapKey
        switch first.wrapped {
        case .integer(let n): firstKey = MapKey(.integer(n))
        case .string(let string): firstKey = MapKey(string)
        default: throw Biscuit.DatalogError.invalidMapKey(first)
        }
        guard let firstValue = try self.parseValue(terminal: .ptBraceR) else {
            throw Biscuit.DatalogError.mapMissingValue
        }
        var elems: [MapKey: Value] = [firstKey: firstValue]
        while true {
            switch try self.eat() {
            case .ptComma: break
            case .ptBraceR: return try Value.map(from: elems)
            case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
            case let token: throw Biscuit.DatalogError.unknownTerm(token!)
            }
            guard let key = try self.parseMapKey() else {
                return try Value.map(from: elems)
            }
            guard case .ptColon = try self.eat() else {
                throw Biscuit.DatalogError.mapMissingValue
            }
            guard let val = try self.parseValue(terminal: .ptBraceR) else {
                throw Biscuit.DatalogError.mapMissingValue
            }
            elems[key] = val
        }
    }

    mutating func parseArray() throws -> Value {
        var elems: [Value] = []
        while let value = try self.parseValue(terminal: .ptBracketR) {
            elems.append(value)
            switch try self.eat() {
            case .ptComma: continue
            case .ptBracketR: return Value.array(from: elems)
            case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
            case let token: throw Biscuit.DatalogError.unknownTerm(token!)
            }
        }
        return Value.array(from: elems)
    }

    mutating func parseValue(terminal: Token) throws -> Value? {
        switch try self.eat() {
        case .keyword(.kwTrue): return Value(true)
        case .keyword(.kwFalse): return Value(false)
        case .keyword(.kwNull): return Value.null
        case .bytes(let data): return Value(data)
        case .date(let date): return Value(date)
        case .number(let n): return Value(.integer(n))
        case .string(let string): return Value(String(string))
        case .ptBraceL: return try self.parseSetOrMap()
        case .ptBracketL: return try self.parseArray()
        case nil: throw Biscuit.DatalogError.unexpectedEndOfCode
        case let token:
            guard token == terminal else {
                throw Biscuit.DatalogError.unknownTerm(token!)
            }
            return nil
        }
    }

    mutating func parseMapKey() throws -> MapKey? {
        guard let value = try self.parseValue(terminal: .ptBraceR) else { return nil }
        switch value.wrapped {
        case .integer(let n): return MapKey(.integer(n))
        case .string(let string): return MapKey(string)
        default: throw Biscuit.DatalogError.invalidMapKey(value)
        }
    }

    enum Expression {
        case term(Term)
        case closure(Closure)
        indirect case unaryOp(OpUnary, Expression)
        indirect case binaryOp(OpBinary, Expression, Expression)
    }

    mutating func eat() throws -> Token? {
        let ret = try self.at()
        self.bump()
        return ret
    }

    mutating func at() throws -> Token? {
        if let token = self.currentToken {
            return token
        } else {
            self.currentToken = try self.lexer.nextToken()
            return self.currentToken
        }
    }

    mutating func bump() {
        self.currentToken = nil
    }
}
