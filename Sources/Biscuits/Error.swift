/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// An error that occurred during attenuation
    public struct AttenuationError: Sendable, Hashable, Error, CustomStringConvertible {
        internal enum ErrorCode: Hashable {
            case cannotAttenuateSealedToken
        }
        let code: ErrorCode

        init(_ code: ErrorCode) {
            self.code = code
        }

        static var cannotAttenuateSealedToken: Self { Self(.cannotAttenuateSealedToken) }

        public var description: String {
            switch self.code {
                case .cannotAttenuateSealedToken: "cannot attenuate a sealed token"
            }
        }
    }

    /// An error that occurred because authorization failed
    public struct AuthorizationError: Sendable, Hashable, Error {
        enum Wrapped: Hashable {
            case check(Check)
            case deny(Policy)
            case noSuccess
        }
        let wrapped: Wrapped

        /// Whether or not this failed because there was no successful allow policy
        public var noSuccessfulPolicy: Bool {
            switch self.wrapped {
                case .noSuccess: true
                default: false
            }
        }

        /// If this failed because of a failed check, the check which failed
        public var failedCheck: Check? {
            switch self.wrapped {
                case .check(let check): check
                default: nil
            }
        }

        /// If this failed because of a deny policy, the policy which caused the failure
        public var failedPolicy: Policy? {
            switch self.wrapped {
                case .deny(let deny): deny
                default: nil
            }
        }

        init() {
            self.wrapped = .noSuccess
        }

        init(check: Check) {
            self.wrapped = .check(check)
        }

        init(deny: Policy) {
            self.wrapped = .deny(deny)
        }
    }

    /// An error that occurred while evaluating a biscuit so that authorization cannot occur
    public struct EvaluationError: Sendable, Hashable, Error, CustomStringConvertible {
        internal enum ErrorCode: Hashable {
            case authorizerWithoutPolicy
            case integerOverflow
            case invalidExpression
            case invalidBinaryOp
            case invalidUnaryOp
            case nonBooleanExpression
            case unknownVariable
            case unknownSymbol
            case unknownForeignFunction(String)
            case typeError
            case wrongArity
            case variableShadowing
            case closureEvaluatedToClosure
            case tooManyFacts
            case tooManyIterations
        }
        let code: ErrorCode

        init(_ code: ErrorCode) {
            self.code = code
        }

        static var authorizerWithoutPolicy: Self { Self(.authorizerWithoutPolicy) }
        static var integerOverflow: Self { Self(.integerOverflow) }
        static var invalidExpression: Self { Self(.invalidExpression) }
        static var invalidBinaryOp: Self { Self(.invalidBinaryOp) }
        static var invalidUnaryOp: Self { Self(.invalidUnaryOp) }
        static var nonBooleanExpression: Self { Self(.nonBooleanExpression) }
        static var unknownVariable: Self { Self(.unknownVariable) }
        static var unknownSymbol: Self { Self(.unknownSymbol) }
        static var typeError: Self { Self(.typeError) }
        static var wrongArity: Self { Self(.wrongArity) }
        static var variableShadowing: Self { Self(.variableShadowing) }
        static var closureEvaluatedToClosure: Self { Self(.closureEvaluatedToClosure) }
        static var tooManyFacts: Self { Self(.tooManyFacts) }
        static var tooManyIterations: Self { Self(.tooManyIterations) }

        static func unknownForeignFunction(_ name: String) -> Self {
            Self(.unknownForeignFunction(name))
        }

        public var description: String {
            switch self.code {
                case .authorizerWithoutPolicy: "authorizer contains no allow or deny policy"
                case .integerOverflow: "integer overflow in authorization"
                case .invalidExpression: "expression was invalid"
                case .invalidBinaryOp: "binary operation was invalid"
                case .invalidUnaryOp: "unary operation was invalid"
                case .nonBooleanExpression: "expression did not evaluate to a boolean expression"
                case .unknownVariable: "variable is unknown"
                case .unknownSymbol: "symbol is unknown"
                case .unknownForeignFunction(let name): "foreign function `\(name)` is unknown"
                case .wrongArity: "closure takes incorrect number of arguments"
                case .typeError: "invalid type"
                case .variableShadowing: "closure parameter shadows another variable"
                case .closureEvaluatedToClosure: "closure evaluated to closure"
                case .tooManyFacts: "evaluating biscuit produced too many facts"
                case .tooManyIterations: "evaluating biscuit required too many iterations"
            }
        }
    }

    /// An error that occurred while parsing or constructing Datalog
    public struct DatalogError: Sendable, Hashable, Error, CustomStringConvertible {
        internal enum ErrorCode: Hashable {
            case errorInLexing
            case missingSemicolon
            case missingLeftParen
            case missingRightParen
            case unknownBlockElement(Token)
            case unknownCheck(Token)
            case unknownMethod(Token)
            case unknownPolicy(Token)
            case unknownPredicate(Token)
            case unknownRuleElement(Token)
            case unknownScope(Token)
            case unknownTerm(Token)
            case unexpectedEndOfCode
            case variableInFact
            case variableInHeadAlone
            case chainedComparisonsWithoutParens
            case invalidMapKey(Value)
            case mapMissingValue
            case setInSet
            case duplicateMapKey
            case invalidHexData
        }
        let code: ErrorCode

        init(_ code: ErrorCode) {
            self.code = code
        }

        static var errorInLexing: Self { Self(.errorInLexing) }
        static var missingSemicolon: Self { Self(.missingSemicolon) }
        static var missingLeftParen: Self { Self(.missingLeftParen) }
        static var missingRightParen: Self { Self(.missingRightParen) }
        static var unexpectedEndOfCode: Self { Self(.unexpectedEndOfCode) }
        static var variableInFact: Self { Self(.variableInFact) }
        static var variableInHeadAlone: Self { Self(.variableInHeadAlone) }
        static var chainedComparisonsWithoutParens: Self { Self(.chainedComparisonsWithoutParens) }
        static var mapMissingValue: Self { Self(.mapMissingValue) }
        static var setInSet: Self { Self(.setInSet) }
        static var duplicateMapKey: Self { Self(.duplicateMapKey) }
        static var invalidHexData: Self { Self(.invalidHexData) }

        static func unknownBlockElement(_ token: Token) -> Self {
            Self(.unknownBlockElement(token))
        }
        static func unknownCheck(_ token: Token) -> Self {
            Self(.unknownCheck(token))
        }
        static func unknownMethod(_ token: Token) -> Self {
            Self(.unknownMethod(token))
        }
        static func unknownPolicy(_ token: Token) -> Self {
            Self(.unknownPolicy(token))
        }
        static func unknownPredicate(_ token: Token) -> Self {
            Self(.unknownPredicate(token))
        }
        static func unknownRuleElement(_ token: Token) -> Self {
            Self(.unknownRuleElement(token))
        }
        static func unknownScope(_ token: Token) -> Self {
            Self(.unknownScope(token))
        }
        static func unknownTerm(_ token: Token) -> Self {
            Self(.unknownTerm(token))
        }
        static func invalidMapKey(_ value: Value) -> Self {
            Self(.invalidMapKey(value))
        }

        public var description: String {
            switch self.code {
                case .errorInLexing: "lexing error occurred while parsing Datalog"
                case .missingSemicolon: "missing semicolon in Datalog"
                case .missingLeftParen: "missing left parenthesis in Datalog"
                case .missingRightParen: "missing right parenthesis in Datalog"
                case .unknownBlockElement(let token): "unknown block element: \(token)"
                case .unknownCheck(let token): "unknown check kind: \(token)"
                case .unknownMethod(let token): "unknown method: \(token)"
                case .unknownPolicy(let token): "unknown policy kind: \(token)"
                case .unknownPredicate(let token): "unknown predicate: \(token)"
                case .unknownRuleElement(let token): "unknown rule element: \(token)"
                case .unknownScope(let token): "unknown trusting scope: \(token)"
                case .unknownTerm(let token): "unknown term: \(token)"
                case .unexpectedEndOfCode: "unexpected end of Datalog code"
                case .variableInFact: "fact contained a variable"
                case .variableInHeadAlone: "variable only present in head of a rule"
                case .chainedComparisonsWithoutParens: "chaining comparisons in Datalog requires parentheses"
                case .invalidMapKey(let v): "invalid map key type: \(v.type)"
                case .mapMissingValue: "map is missing value"
                case .setInSet: "set contains a set"
                case .duplicateMapKey: "map contains duplicate key"
                case .invalidHexData: "invalid hexadecimal string"
            }
        }
    }

    /// An error that occurred while validating the serialized data representation of a Biscuit
    public struct ValidationError: Sendable, Hashable, Error, CustomStringConvertible {
        internal enum ErrorCode: Hashable {
            case invalidProof
            case invalidSignature
            case invalidExternalSignature
            case invalidSealingSignature
            case invalidQueryHead
            case invalidVersion
            case missingAuthority
            case missingBlockData
            case missingExternalSignature
            case missingFFI
            case missingPayload
            case missingPreviousSignature
            case missingProof
            case missingPublicKey
            case missingSignature
            case unknownRootKey
            case unknownPublicKey
            case unknownSymbol
            case thirdPartySignedAuthority
            case deprecatedThirdPartySignature

            case duplicatePublicKey
            case duplicateSymbol
            case missingOp
            case missingPredicate
            case missingRuleHead
            case missingScope
            case missingTerm
            case missingVersion
            case unboundVariableInHead
            case variableInFact
            case setInSet
            case duplicateMapKey
            case invalidHexData
            case invalidBase64URLString
        }
        let code: ErrorCode

        init(_ code: ErrorCode) {
            self.code = code
        }

        static var invalidProof: Self { Self(.invalidProof) }
        static var invalidSignature: Self { Self(.invalidSignature) }
        static var invalidExternalSignature: Self { Self(.invalidExternalSignature) }
        static var invalidSealingSignature: Self { Self(.invalidSealingSignature) }
        static var invalidQueryHead: Self { Self(.invalidQueryHead) }
        static var invalidVersion: Self { Self(.invalidVersion) }
        static var missingAuthority: Self { Self(.missingAuthority) }
        static var missingBlockData: Self { Self(.missingBlockData) }
        static var missingExternalSignature: Self { Self(.missingExternalSignature) }
        static var missingFFI: Self { Self(.missingFFI) }
        static var missingPayload: Self { Self(.missingPayload) }
        static var missingPreviousSignature: Self { Self(.missingPreviousSignature) }
        static var missingProof: Self { Self(.missingProof) }
        static var missingPublicKey: Self { Self(.missingPublicKey) }
        static var missingSignature: Self { Self(.missingSignature) }
        static var unknownRootKey: Self { Self(.unknownRootKey) }
        static var unknownPublicKey: Self { Self(.unknownSymbol) }
        static var unknownSymbol: Self { Self(.unknownSymbol) }
        static var thirdPartySignedAuthority: Self { Self(.thirdPartySignedAuthority) }
        static var deprecatedThirdPartySignature: Self { Self(.deprecatedThirdPartySignature) }

        static var duplicatePublicKey: Self { Self(.duplicatePublicKey) }
        static var duplicateSymbol: Self { Self(.duplicateSymbol) }
        static var missingOp: Self { Self(.missingOp) }
        static var missingPredicate: Self { Self(.missingPredicate) }
        static var missingRuleHead: Self { Self(.missingRuleHead) }
        static var missingScope: Self { Self(.missingScope) }
        static var missingTerm: Self { Self(.missingTerm) }
        static var missingVersion: Self { Self(.missingVersion) }
        static var unboundVariableInHead: Self { Self(.unboundVariableInHead) }
        static var variableInFact: Self { Self(.variableInFact) }
        static var setInSet: Self { Self(.setInSet) }
        static var duplicateMapKey: Self { Self(.duplicateMapKey) }
        static var invalidHexData: Self { Self(.invalidHexData) }
        static var invalidBase64URLString: Self { Self(.invalidBase64URLString) }

        public var description: String {
            switch self.code {
                case .invalidProof: "Biscuit proof is invalid"
                case .invalidSignature: "Biscuit contains invalid signature"
                case .invalidExternalSignature: "Biscuit contains invalid third party signature"
                case .invalidSealingSignature: "Biscuit is sealed with invalid signature"
                case .invalidQueryHead: "Checks must have query as their head"
                case .invalidVersion: "Biscuit version is invalid"
                case .unknownRootKey: "Biscuit signed with unknown root key"
                case .unknownPublicKey: "Biscuit contains unknown public key"
                case .unknownSymbol: "Biscuit contains unknown symbol"
                case .missingAuthority: "Biscuit is missing an authority block"
                case .missingBlockData: " Biscuit block is missing Datalog contents"
                case .missingExternalSignature: "Biscuit ThirdPartyBlockContents is missing third party signature"
                case .missingFFI: "Biscuit is expression missing FFI name"
                case .missingPayload: "Biscuit ThirdPartyBlockContents is missing payload"
                case .missingPreviousSignature: "Biscuit ThirdPartyBlockRequest is missing previous signature"
                case .missingProof: "Biscuit is missing proof"
                case .missingPublicKey: "Biscuit block is missing a public key"
                case .missingSignature: "Biscuit block is missing a signature"
                case .duplicatePublicKey: "Biscuit block duplicates public key"
                case .duplicateSymbol: "Biscuit block duplicates symbol"
                case .missingOp: "Biscuit expression missing operation"
                case .missingPredicate: "Biscuit predicate missing name"
                case .missingRuleHead: "Biscuit rule missing head"
                case .missingScope: "Biscuit statement scope is missing"
                case .missingTerm: "Biscuit term is missing"
                case .missingVersion: "Biscuit is missing version"
                case .unboundVariableInHead: "Variable only present in head of a rule"
                case .thirdPartySignedAuthority: "Authority block has third party signature"
                case .deprecatedThirdPartySignature: "Deprecated form of third party signature"
                case .variableInFact: "Fact contained a free variable"
                case .setInSet: "Set contains a set"
                case .duplicateMapKey: "Map contains duplicate keys"
                case .invalidHexData: "Invalid character in hexadecimal string"
                case .invalidBase64URLString: "Invalid Base64URL encoded string"
            }
        }
    }
}
