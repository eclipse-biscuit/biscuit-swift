/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
extension Biscuit {
    /// Restrictions on the features a Biscuit may contain, enforced while it is deserialized
    ///
    /// Settings which apply to the token as a whole are properties of the AllowList itself, while
    /// settings which apply within each block are part of a ``PerBlock`` allow list. Separate
    /// ``PerBlock`` allow lists are used for the authority block and for attenuations, so that
    /// attenuations can be restricted more tightly than the authority block.
    ///
    /// Every setting allows everything by default; start from ``allowEverything`` or ``init()`` and
    /// restrict only the features you need to:
    ///
    /// ```swift
    /// var allowList = Biscuit.AllowList()
    /// allowList.maximumBlocks = 4
    /// allowList.attenuations.allowClosures = false
    /// ```
    ///
    /// A Biscuit which contains a feature that is not allowed fails to deserialize with an
    /// ``AllowListError``.
    public struct AllowList: Sendable, Hashable {
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

        /// The allow list for the authority block
        public var authority: PerBlock = .allowEverything
        /// The allow list for each attenuation
        public var attenuations: PerBlock = .allowEverything

        /// Construct an AllowList which allows all features
        public init() {}

        /// An AllowList which allows all features
        public static let allowEverything = AllowList()

        /// The features allowed within a single block of a token
        public struct PerBlock: Sendable, Hashable {
            /// Whether expressions may contain closures
            public var allowClosures: Bool = true

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

            /// Construct a PerBlock allow list which allows all features
            public init() {}

            /// A PerBlock allow list which allows all features
            public static let allowEverything = PerBlock()
        }
    }
}
