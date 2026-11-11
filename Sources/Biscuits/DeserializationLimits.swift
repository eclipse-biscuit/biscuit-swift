/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// Restrictions on the features a Biscuit may contain, enforced while it is deserialized
    ///
    /// Settings which apply to the token as a whole are properties of DeserializationLimits itself,
    /// while settings which apply within each block are part of ``PerBlock``. Separate ``PerBlock``
    /// limits are used for the authority block and for attenuations, so that attenuations can be
    /// restricted more tightly than the authority block.
    ///
    /// Every setting allows everything by default; start from ``allowEverything`` or ``init()`` and
    /// restrict only the features you need to:
    ///
    /// ```swift
    /// var limits = Biscuit.DeserializationLimits()
    /// limits.maximumBlocks = 4
    /// limits.attenuations.allowClosures = false
    /// ```
    ///
    /// Alternatively, start from ``allowNothing`` and enable only the features you need.
    ///
    /// A Biscuit which contains a feature that is not allowed fails to deserialize with a
    /// ``DeserializationLimitError``.
    public struct DeserializationLimits: Sendable, Hashable {
        /// Whether attenuations may be signed by a third party
        public var allowAttenuationsWithExternalSignatures: Bool = true
        /// Whether attenuations may be signed without a third party
        public var allowAttenuationsWithoutExternalSignatures: Bool = true
        /// Whether the token may be sealed
        public var allowSealedTokens: Bool = true
        /// Whether the token may be unsealed
        public var allowUnsealedTokens: Bool = true

        /// The maximum size of the serialized token, in bytes
        public var maximumTokenSize: Int = .max
        /// The maximum number of blocks, including the authority block
        public var maximumBlocks: Int = .max

        /// The minimum signature version for each block of the token
        public var minimumSignatureVersion: Int = 0

        /// The signing algorithms allowed for the keys which sign each block of the token and its
        /// proof
        public var allowedInternalSigningAlgorithms: Set<SigningAlgorithm>? = nil
        /// The signing algorithms allowed for the third party keys which sign attenuations
        public var allowedExternalSigningAlgorithms: Set<SigningAlgorithm>? = nil

        /// The limits for the authority block
        public var authority: PerBlock = .allowEverything
        /// The limits for each attenuation
        public var attenuations: PerBlock = .allowEverything

        /// Construct DeserializationLimits which allow all features
        public init() {}

        /// DeserializationLimits which allow all features
        public static let allowEverything = DeserializationLimits()

        /// DeserializationLimits which allow no features
        ///
        /// Future versions of this library may add features which will be disallowed by these
        /// limits; tokens accepted by limits built from these may be rejected after upgrading until
        /// those features are enabled.
        public static let allowNothing: DeserializationLimits = {
            var limits = DeserializationLimits()
            limits.allowAttenuationsWithExternalSignatures = false
            limits.allowAttenuationsWithoutExternalSignatures = false
            limits.allowSealedTokens = false
            limits.allowUnsealedTokens = false
            limits.maximumTokenSize = 0
            limits.maximumBlocks = 0
            limits.minimumSignatureVersion = 1
            limits.allowedInternalSigningAlgorithms = []
            limits.allowedExternalSigningAlgorithms = []
            limits.authority = .allowNothing
            limits.attenuations = .allowNothing
            return limits
        }()

        /// The features allowed within a single block of a token
        public struct PerBlock: Sendable, Hashable {
            /// Whether expressions may contain closures
            public var allowClosures: Bool = true

            /// The maximum size of a Datalog block in bytes
            public var maximumBlockSize: Int = .max
            /// The maximum number of facts in the block
            public var maximumFacts: Int = .max
            /// The maximum number of rules in the block
            public var maximumRules: Int = .max
            /// The maximum number of checks in the block
            public var maximumChecks: Int = .max
            /// The maximum number of symbols in the block's symbol table
            public var maximumSymbols: Int = .max
            /// The maximum number of public keys in the block's public key table
            public var maximumPublicKeys: Int = .max
            /// The maximum length of the block's context string
            public var maximumContextLength: Int = .max
            /// The maximum number of queries in each check
            public var maximumQueriesPerCheck: Int = .max
            /// The maximum number of predicates in the body of each rule or check query
            public var maximumPredicatesPerBody: Int = .max
            /// The maximum number of expressions in the body of each rule or check query
            public var maximumExpressionsPerBody: Int = .max
            /// The maximum number of ops in each expression, including the ops of any closures
            /// nested within it
            public var maximumOpsPerExpression: Int = .max
            /// The maximum number of terms in each fact or predicate
            public var maximumTermsPerPredicate: Int = .max
            /// The maximum length of each name, including predicate names, variable names, closure
            /// parameter names, and foreign function names
            public var maximumNameLength: Int = .max
            /// The maximum length of each bytes value
            public var maximumBytesLength: Int = .max
            /// The maximum length of each string value
            public var maximumStringLength: Int = .max
            /// The maximum number of elements in each set, not counting the elements of nested
            /// collections
            public var maximumSetLength: Int = .max
            /// The maximum number of elements in each array, not counting the elements of nested
            /// collections
            public var maximumArrayLength: Int = .max
            /// The maximum number of entries in each map, not counting the entries of nested
            /// collections
            public var maximumMapLength: Int = .max

            /// The binary operations allowed in expressions
            public var allowedBinaryOperations: Set<BinaryOperation>? = nil
            /// The unary operations allowed in expressions
            public var allowedUnaryOperations: Set<UnaryOperation>? = nil
            /// The names of the foreign functions allowed to be called with no arguments
            public var allowedUnaryExternalFunctions: Set<String>? = nil
            /// The names of the foreign functions allowed to be called with one argument
            public var allowedBinaryExternalFunctions: Set<String>? = nil
            /// The kinds of values allowed as terms
            public var allowedTermTypes: Set<Value.Kind>? = nil
            /// The kinds of keys allowed in maps
            public var allowedMapKeyTypes: Set<MapKey.Kind>? = nil
            /// The kinds of scopes allowed to be trusted by the block, its rules, and its checks
            public var allowedTrustedScopes: Set<TrustedScope.Kind>? = nil
            /// The kinds of checks allowed
            public var allowedCheckKinds: Set<Check.Kind>? = nil

            /// Construct PerBlock limits which allow all features
            public init() {}

            /// PerBlock limits which allow all features
            public static let allowEverything = PerBlock()

            /// PerBlock limits which allow no features
            ///
            /// Future versions of this library may add settings, which will be disallowed by these
            /// limits.
            public static let allowNothing: PerBlock = {
                var limits = PerBlock()
                limits.allowClosures = false
                limits.maximumBlockSize = 0
                limits.maximumFacts = 0
                limits.maximumRules = 0
                limits.maximumChecks = 0
                limits.maximumSymbols = 0
                limits.maximumPublicKeys = 0
                limits.maximumContextLength = 0
                limits.maximumQueriesPerCheck = 0
                limits.maximumPredicatesPerBody = 0
                limits.maximumExpressionsPerBody = 0
                limits.maximumOpsPerExpression = 0
                limits.maximumTermsPerPredicate = 0
                limits.maximumNameLength = 0
                limits.maximumBytesLength = 0
                limits.maximumStringLength = 0
                limits.maximumSetLength = 0
                limits.maximumArrayLength = 0
                limits.maximumMapLength = 0
                limits.allowedBinaryOperations = []
                limits.allowedUnaryOperations = []
                limits.allowedUnaryExternalFunctions = []
                limits.allowedBinaryExternalFunctions = []
                limits.allowedTermTypes = []
                limits.allowedMapKeyTypes = []
                limits.allowedTrustedScopes = []
                limits.allowedCheckKinds = []
                return limits
            }()
        }
    }
}
