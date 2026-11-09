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

    /// An error that occurred because a Biscuit exceeded the DeserializationLimits it was deserialized with
    public struct DeserializationLimitError: Sendable, Hashable, Error, CustomStringConvertible {
        internal enum ErrorCode: Hashable {
            case tokenTooLarge
            case tooManyBlocks
            case tooManyFacts
            case tooManyRules
            case tooManyChecks
            case tooManySymbols
            case tooManyPublicKeys
            case tooManyQueries
            case tooManyPredicates
            case tooManyExpressions
            case tooManyOps
            case tooManyTerms
            case nameTooLong
            case stringTooLong
            case bytesTooLong
            case setTooLong
            case arrayTooLong
            case mapTooLong
            case closuresNotAllowed
            case signatureVersionTooLow
            case internalSigningAlgorithmNotAllowed
            case externalSigningAlgorithmNotAllowed
            case binaryOperationNotAllowed
            case unaryOperationNotAllowed
            case externalFunctionNotAllowed
            case termTypeNotAllowed
            case mapKeyTypeNotAllowed
            case trustedScopeNotAllowed
            case contextTooLong
            case checkKindNotAllowed
            case sealedTokensNotAllowed
            case unsealedTokensNotAllowed
            case attenuationsWithExternalSignaturesNotAllowed
            case attenuationsWithoutExternalSignaturesNotAllowed
        }
        let code: ErrorCode

        init(_ code: ErrorCode) {
            self.code = code
        }

        static var tokenTooLarge: Self { Self(.tokenTooLarge) }
        static var tooManyBlocks: Self { Self(.tooManyBlocks) }
        static var tooManyFacts: Self { Self(.tooManyFacts) }
        static var tooManyRules: Self { Self(.tooManyRules) }
        static var tooManyChecks: Self { Self(.tooManyChecks) }
        static var tooManySymbols: Self { Self(.tooManySymbols) }
        static var tooManyPublicKeys: Self { Self(.tooManyPublicKeys) }
        static var tooManyQueries: Self { Self(.tooManyQueries) }
        static var tooManyPredicates: Self { Self(.tooManyPredicates) }
        static var tooManyExpressions: Self { Self(.tooManyExpressions) }
        static var tooManyOps: Self { Self(.tooManyOps) }
        static var tooManyTerms: Self { Self(.tooManyTerms) }
        static var nameTooLong: Self { Self(.nameTooLong) }
        static var stringTooLong: Self { Self(.stringTooLong) }
        static var bytesTooLong: Self { Self(.bytesTooLong) }
        static var setTooLong: Self { Self(.setTooLong) }
        static var arrayTooLong: Self { Self(.arrayTooLong) }
        static var mapTooLong: Self { Self(.mapTooLong) }
        static var closuresNotAllowed: Self { Self(.closuresNotAllowed) }
        static var signatureVersionTooLow: Self { Self(.signatureVersionTooLow) }
        static var internalSigningAlgorithmNotAllowed: Self { Self(.internalSigningAlgorithmNotAllowed) }
        static var externalSigningAlgorithmNotAllowed: Self { Self(.externalSigningAlgorithmNotAllowed) }
        static var binaryOperationNotAllowed: Self { Self(.binaryOperationNotAllowed) }
        static var unaryOperationNotAllowed: Self { Self(.unaryOperationNotAllowed) }
        static var externalFunctionNotAllowed: Self { Self(.externalFunctionNotAllowed) }
        static var termTypeNotAllowed: Self { Self(.termTypeNotAllowed) }
        static var mapKeyTypeNotAllowed: Self { Self(.mapKeyTypeNotAllowed) }
        static var trustedScopeNotAllowed: Self { Self(.trustedScopeNotAllowed) }
        static var contextTooLong: Self { Self(.contextTooLong) }
        static var checkKindNotAllowed: Self { Self(.checkKindNotAllowed) }
        static var sealedTokensNotAllowed: Self { Self(.sealedTokensNotAllowed) }
        static var unsealedTokensNotAllowed: Self { Self(.unsealedTokensNotAllowed) }
        static var attenuationsWithExternalSignaturesNotAllowed: Self {
            Self(.attenuationsWithExternalSignaturesNotAllowed)
        }
        static var attenuationsWithoutExternalSignaturesNotAllowed: Self {
            Self(.attenuationsWithoutExternalSignaturesNotAllowed)
        }

        public var description: String {
            switch self.code {
            case .tokenTooLarge: "Biscuit is too large"
            case .tooManyBlocks: "Biscuit contains too many blocks"
            case .tooManyFacts: "Biscuit block contains too many facts"
            case .tooManyRules: "Biscuit block contains too many rules"
            case .tooManyChecks: "Biscuit block contains too many checks"
            case .tooManySymbols: "Biscuit block contains too many symbols"
            case .tooManyPublicKeys: "Biscuit block contains too many public keys"
            case .tooManyQueries: "Biscuit check contains too many queries"
            case .tooManyPredicates: "Biscuit rule or query body contains too many predicates"
            case .tooManyExpressions: "Biscuit rule or query body contains too many expressions"
            case .tooManyOps: "Biscuit expression contains too many operations"
            case .tooManyTerms: "Biscuit fact or predicate contains too many terms"
            case .nameTooLong: "Biscuit contains a name which is too long"
            case .stringTooLong: "Biscuit contains a string which is too long"
            case .bytesTooLong: "Biscuit contains a bytes value which is too long"
            case .setTooLong: "Biscuit contains a set which is too long"
            case .arrayTooLong: "Biscuit contains an array which is too long"
            case .mapTooLong: "Biscuit contains a map which is too long"
            case .closuresNotAllowed: "Biscuit contains closures, which are not allowed"
            case .signatureVersionTooLow: "Biscuit block uses a signature version which is too low"
            case .internalSigningAlgorithmNotAllowed: "Biscuit block is signed with an algorithm which is not allowed"
            case .externalSigningAlgorithmNotAllowed:
                "Biscuit block has a third party signature with an algorithm which is not allowed"
            case .binaryOperationNotAllowed: "Biscuit contains a binary operation which is not allowed"
            case .unaryOperationNotAllowed: "Biscuit contains a unary operation which is not allowed"
            case .externalFunctionNotAllowed: "Biscuit calls a foreign function which is not allowed"
            case .termTypeNotAllowed: "Biscuit contains a term of a type which is not allowed"
            case .mapKeyTypeNotAllowed: "Biscuit contains a map key of a type which is not allowed"
            case .trustedScopeNotAllowed: "Biscuit trusts a scope which is not allowed"
            case .contextTooLong: "Biscuit block contains a context which is too long"
            case .checkKindNotAllowed: "Biscuit contains a kind of check which is not allowed"
            case .sealedTokensNotAllowed: "Biscuit is sealed, which is not allowed"
            case .unsealedTokensNotAllowed: "Biscuit is not sealed, which is not allowed"
            case .attenuationsWithExternalSignaturesNotAllowed:
                "Biscuit contains attenuations with external signatures, which are not allowed"
            case .attenuationsWithoutExternalSignaturesNotAllowed:
                "Biscuit contains attenuations without external signatures, which are not allowed"
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
            case tooManySteps
            case regexUnsupported
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
        static var tooManySteps: Self { Self(.tooManySteps) }
        static var regexUnsupported: Self { Self(.regexUnsupported) }

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
            case .tooManySteps: "evaluating biscuit required too many steps"
            case .regexUnsupported: "regular expressions are not supported in this build"
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
            case invalidIndex
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
        static var invalidIndex: Self { Self(.invalidIndex) }
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
            case .invalidIndex: "Biscuit contains an out of range symbol or public key index"
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
