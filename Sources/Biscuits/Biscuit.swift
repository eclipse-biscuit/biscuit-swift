/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A Biscuit authorization token
public struct Biscuit: Sendable, Hashable {
    let interner: InternmentTables
    let proof: Proof

    /// The ID of the key used to sign the authority block of this Biscuit, if one is specified
    public var rootKeyID: RootKeyID?
    /// The authority block of this Biscuit
    public let authority: Block
    /// All of the attenuations on this Biscuit
    public let attenuations: [Block]

    /// Creates a new Biscuit.
    ///
    /// - Parameters:
    ///   - rootKey: the key that will sign the authority block
    ///   - rootKeyID: the identifier of the rootKey
    ///   - algorithm: which signing algorithm to use to seal or attenuate this Biscuit
    ///   - context: context information which can be carried with this Biscuit
    ///   - using: the datalog contents of the authority block
    /// - Throws: Signing may throw an error
    public init<Key: PrivateKey>(
        rootKey: Key,
        rootKeyID: RootKeyID? = nil,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil,
        @DatalogBlock using datalog: () throws -> DatalogBlock
    ) throws {
        try self.init(
            authorityBlock: datalog(),
            rootKey: rootKey,
            rootKeyID: rootKeyID,
            algorithm: algorithm,
            context: context
        )
    }

    /// Creates a new Biscuit.
    ///
    /// - Parameters:
    ///   - authorityBlock: the datalog contents of the authority block, as a String
    ///   - rootKey: the key that will sign the authority block
    ///   - rootKeyID: the identifier of the rootKey
    ///   - algorithm: which signing algorithm to use to seal or attenuate this Biscuit
    ///   - context: context information which can be carried with this Biscuit
    /// - Throws: Parsing the authorityBlock string may throw a `DatalogError` and signing may
    /// throw an error
    public init<Key: PrivateKey>(
        authorityBlock datalog: String,
        rootKey: Key,
        rootKeyID: RootKeyID? = nil,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws {
        try self.init(
            authorityBlock: DatalogBlock(datalog),
            rootKey: rootKey,
            rootKeyID: rootKeyID,
            algorithm: algorithm,
            context: context
        )
    }

    /// Creates a new Biscuit.
    ///
    /// - Parameters:
    ///   - authorityBlock: the datalog contents of the authority block
    ///   - rootKey: the key that will sign the authority block
    ///   - rootKeyID: the identifier of the rootKey
    ///   - algorithm: which signing algorithm to use to seal or attenuate this Biscuit
    ///   - context: context information which can be carried with this Biscuit
    /// - Throws: Signing may throw an error
    public init<Key: PrivateKey>(
        authorityBlock: DatalogBlock,
        rootKey: Key,
        rootKeyID: RootKeyID? = nil,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws {
        var interner = InternmentTables()
        var authority = authorityBlock
        authority.attachToBiscuit(interner: &interner.primary, context: context)
        let nextKey = InternalPrivateKey(algorithm: algorithm)
        self.rootKeyID = rootKeyID
        self.authority = try Block(
            datalog: authority,
            nextKey: nextKey.publicKey,
            key: rootKey,
            interner: interner.primary
        )
        self.interner = interner
        self.attenuations = []
        self.proof = .nextSecret(nextKey)
    }

    /// Deserializes a Biscuit from its serialized representation, assuming that a specific key
    /// was used as the root key for this Biscuit.
    ///
    /// - Parameters:
    ///   - serializedData: the serialized representation of the Biscuit
    ///   - rootKey: the key that is expected to have signed this Biscuit
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if the
    /// serializedData is not in the proper format or signatures are not valid
    public init<Key: PublicKey>(serializedData: Data, rootKey: Key) throws {
        try self.init(serializedData: serializedData, getRootKey: { _ in rootKey })
    }

    /// Deserializes a Biscuit from its serialized representation, using a RootKeyID in the Biscuit
    /// to determine which key should have been used to sign it.
    ///
    /// - Parameters:
    ///   - serializedData: the serialized representation of the Biscuit
    ///   - getRootKey: returns the key that is expected to have signed this Biscuit; if the
    ///   Biscuit contains a RootKeyID, that is passed as a parameter
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if the
    /// serializedData is not in the proper format or signatures are not valid
    public init<Key: PublicKey>(serializedData: Data, getRootKey: (RootKeyID?) -> Key?) throws {
        let proto = try Biscuit_Format_Schema_Biscuit(serializedBytes: serializedData)
        guard proto.hasAuthority else {
            throw ValidationError.missingAuthority
        }
        if proto.hasRootKeyID {
            self.rootKeyID = RootKeyID(Int(proto.rootKeyID))
        } else {
            self.rootKeyID = nil
        }
        guard let rootKey = getRootKey(self.rootKeyID) else {
            throw ValidationError.unknownRootKey
        }
        var interner = InternmentTables()
        self.authority = try Block(
            proto: proto.authority,
            key: rootKey,
            interner: &interner
        )
        var lastBlock = self.authority
        self.attenuations = try proto.blocks.enumerated().map {
            lastBlock = try Block(
                proto: $1,
                lastBlock: lastBlock,
                blockID: $0 + 1,
                interner: &interner
            )
            return lastBlock
        }
        self.proof = try Proof(proto: proto.proof, algorithm: lastBlock.nextKey.algorithm)
        try self.proof.isValidProof(for: lastBlock, interner: interner.blockTable(for: self.attenuations.count))
        self.interner = interner
    }

    /// Deserializes a Biscuit from its base64url representation, assuming that a specific key
    /// was used as the root key for this Biscuit.
    /// - Parameters:
    ///   - base64URLEncoded: the base64url representation of the Biscuit
    ///   - rootKey: the key that is expected to have signed this Biscuit
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if
    /// base64URLEncoded or the underlying data is not in the proper format or signatures are not valid
    public init<Key: PublicKey>(base64URLEncoded: String, rootKey: Key) throws {
        try self.init(base64URLEncoded: base64URLEncoded, getRootKey: { _ in rootKey })
    }

    /// Deserializes a Biscuit from its base64url representation, using a RootKeyID in the Biscuit
    /// to determine which key should have been used to sign it.
    ///
    /// - Parameters:
    ///   - serializedData: the base64url representation of the Biscuit
    ///   - getRootKey: returns the key that is expected to have signed this Biscuit; if the
    ///   Biscuit contains a RootKeyID, that is passed as a parameter
    /// - Throws: Validation may throw a protobuf error or a `ValidationError` if
    /// base64url or the underlying data is not in the proper format or signatures are not valid
    public init<Key: PublicKey>(base64URLEncoded: String, getRootKey: (RootKeyID?) -> Key?) throws {
        // Translate base64url into base64, ignoring padding, as defined in RFC4648.
        let base64Encoded =
            base64URLEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        guard let data = Data(base64Encoded: base64Encoded) else {
            throw ValidationError.invalidBase64URLString
        }

        try self.init(serializedData: data, getRootKey: getRootKey)
    }

    init(_ parent: Biscuit, _ attenuations: [Block], _ interner: InternmentTables, _ proof: Proof) {
        self.interner = interner
        self.rootKeyID = parent.rootKeyID
        self.authority = parent.authority
        self.attenuations = attenuations
        self.proof = proof
    }

    init(unverifiedBiscuit: UnverifiedBiscuit) {
        self.interner = unverifiedBiscuit.interner
        self.proof = unverifiedBiscuit.proof
        self.rootKeyID = unverifiedBiscuit.rootKeyID
        self.authority = unverifiedBiscuit.authority
        self.attenuations = unverifiedBiscuit.attenuations
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    ///   - using: the datalog contents of the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated(
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil,
        @DatalogBlock using datalog: () throws -> DatalogBlock
    ) throws -> Biscuit {
        try self.attenuated(using: datalog(), algorithm: algorithm, context: context)
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    ///   - using: the datalog contents of the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated<Key: PrivateKey>(
        thirdPartyKey: Key,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil,
        @DatalogBlock using datalog: () throws -> DatalogBlock
    ) throws -> Biscuit {
        try self.attenuated(
            using: datalog(),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - using: the datalog contents of the attenuation, as a String
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated(
        using datalog: String,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> Biscuit {
        try self.attenuated(
            using: DatalogBlock(datalog),
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - using: the datalog contents of the attenuation, as a String
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated<Key: PrivateKey>(
        using datalog: String,
        thirdPartyKey: Key,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> Biscuit {
        try self.attenuated(
            using: DatalogBlock(datalog),
            thirdPartyKey: thirdPartyKey,
            algorithm: algorithm,
            context: context
        )
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - using: the datalog contents of the attenuation, as a String
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed or a `DatalogError` if
    /// the datalog string cannot be parsed, and signing may throw an error
    public func attenuated(
        using datalog: DatalogBlock,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> Biscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw AttenuationError.cannotAttenuateSealedToken
        }
        var interner = self.interner
        var attenuation = datalog
        attenuation.attachToBiscuit(interner: &interner.primary, context: context)
        let nextKey = InternalPrivateKey(algorithm: algorithm)
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        var attenuations = self.attenuations
        try attenuations.append(
            Block(
                datalog: attenuation,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: lastSig,
                externalSignature: nil,
                interner: interner.primary
            )
        )
        return Biscuit(self, attenuations, interner, .nextSecret(nextKey))
    }

    /// Attenuate this Biscuit, producing a new Biscuit which has been attenuated to a smaller
    /// scope. This Biscuit remains unattenuated.
    ///
    /// - Parameters:
    ///   - using: the datalog contents of the attenuation
    ///   - thirdPartyKey: this key will be used to sign the attenuation
    ///   - algorithm: the algorithm that will be used to further attenuate the new Biscuit
    ///   - context: context information which can be carried with the attenuation
    /// - Returns: the attenuated Biscuit
    /// - Throws: May throw an `AttenuationError` if the Biscuit is sealed and signing may throw an
    /// error
    public func attenuated<Key: PrivateKey>(
        using datalog: DatalogBlock,
        thirdPartyKey: Key,
        algorithm: SigningAlgorithm = .ed25519,
        context: String? = nil
    ) throws -> Biscuit {
        guard case .nextSecret(let lastKey) = self.proof else {
            throw AttenuationError.cannotAttenuateSealedToken
        }
        var blockInterner = BlockInternmentTable()
        var attenuation = datalog
        attenuation.attachToBiscuit(interner: &blockInterner, context: context)
        let nextKey = InternalPrivateKey(algorithm: algorithm)
        let lastSig = self.attenuations.last?.signature ?? self.authority.signature
        var attenuations = self.attenuations
        let externalSignature = try Block.ExternalSignature(
            block: attenuation,
            lastSig: lastSig,
            thirdPartyKey: thirdPartyKey,
            interner: blockInterner
        )
        try attenuations.append(
            Block(
                datalog: attenuation,
                nextKey: nextKey.publicKey,
                lastKey: lastKey,
                lastSig: lastSig,
                externalSignature: externalSignature,
                interner: blockInterner
            )
        )
        var interner = self.interner
        interner.setBlockTable(blockInterner, for: attenuations.count)
        return Biscuit(self, attenuations, interner, .nextSecret(nextKey))
    }

    /// Seal this Biscuit, producing a new Biscuit which cannot be attenuated further. This Biscuit
    /// remains unchanged.
    ///
    /// - Returns: the sealed Biscuit
    /// - Throws: Signing may throw an error
    public func sealed() throws -> Biscuit {
        if case .nextSecret(let key) = self.proof {
            let sig = try key.sealingSignature(
                for: self.attenuations.last ?? self.authority,
                interner: self.interner.blockTable(for: self.attenuations.count)
            )
            return Biscuit(self, self.attenuations, self.interner, .finalSignature(sig))
        } else {
            return self
        }
    }

    /// Authorize this Biscuit
    /// - Parameter limitedBy: Limitations on the runtime for this query
    /// - Parameter authorizer: the authorizer datalog used to validate this Biscuit
    /// - Returns: The Authorization describing the successful authorization attempt
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, or an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated
    @discardableResult
    public func authorize(
        limitedBy: Authorizer.Limits = Authorizer.Limits.noLimits,
        @Authorizer using datalog: () throws -> Authorizer
    ) throws -> Authorization {
        var authorizer = try datalog()
        authorizer.limits = limitedBy
        return try self.authorize(using: authorizer)
    }

    /// Authorize this Biscuit
    /// - Parameter using: the authorizer datalog used to validate this Biscuit, as a String
    /// - Parameter limitedBy: Limitations on the runtime for this query
    /// - Returns: The Authorization describing the successful authorization attempt
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated, or a `DatalogError`
    /// if the Datalog string fails to parse
    @discardableResult
    public func authorize(
        using datalog: String,
        limitedBy: Authorizer.Limits = Authorizer.Limits.noLimits
    ) throws -> Authorization {
        try self.authorize(using: Authorizer(datalog, limitedBy: limitedBy))
    }

    /// Authorize this Biscuit
    /// - Parameter using: the authorizer datalog used to validate this Biscuit
    /// - Returns: The Authorization describing the successful authorization attempt
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated
    @discardableResult
    public func authorize(using authorizer: Authorizer) throws -> Authorization {
        let facts = try Resolution(biscuit: self, authorizer: authorizer)
        try self.validateChecks(facts)
        return try authorizer.validateChecksAndPolicies(facts)
    }

    /// Serialize this Biscuit to its data representation
    /// - Returns: the data representation of this Biscuit
    /// - Throws: May throw an error if protobuf serialization fails
    public func serializedData() throws -> Data {
        try self.proto().serializedData()
    }

    /// Serialize this Biscuit to its base64url encoded representation
    /// - Returns: the base64url encoded representation of this Biscuit
    /// - Throws: May thow an error if protobuf serialization fails
    public func base64URLEncoded() throws -> String {
        let base64Encoded = try self.proto().serializedData().base64EncodedString()
        // Translate base64 into base64url, ignoring padding, as defined in RFC4648.
        return
            base64Encoded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    /// Whether or not this Biscuit has been sealed
    public var isSealed: Bool { self.proof.isSealed }

    func proto() throws -> Biscuit_Format_Schema_Biscuit {
        var proto = Biscuit_Format_Schema_Biscuit()
        if let rootKeyID = self.rootKeyID {
            proto.rootKeyID = rootKeyID.rawValue
        }
        proto.authority = try self.authority.proto(interner: self.interner.primary)
        proto.blocks = try self.attenuations.enumerated().map {
            try $1.proto(interner: self.interner.blockTable(for: $0 + 1))
        }
        proto.proof = self.proof.proto
        return proto
    }

    /// An identifier assigned to a key used to sign Biscuits
    ///
    /// This value will be truncated to four bytes when serializing a Biscuit, so it must be between
    /// -2,147,483,648 and 2,147,483,647 inclusive.
    public struct RootKeyID: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
        let rawValue: UInt32

        /// Initialize a root key ID from an integer
        public init(_ value: Int) {
            self.rawValue = UInt32(bitPattern: Int32(truncatingIfNeeded: value))
        }

        /// The integer value of this root key
        public var value: Int { Int(self.rawValue) }

        public var description: String { String(describing: self.rawValue) }
        public var debugDescription: String { String(reflecting: self.rawValue) }
    }

    /// The result of a successful authorization check on a Biscuit
    public struct Authorization: Sendable, Hashable {
        /// Which policy statement passed, resulting in the successful authorization
        public let successfulPolicy: Policy

        init(policy: Policy) {
            self.successfulPolicy = policy
        }
    }

    /// Query the biscuit to check if a certain statement holds true
    /// - Parameter using: The Check to use to query the biscuit
    /// - Parameter limitedBy: Limitations on the runtime for this query
    /// - Returns: Whether or not the query succeeded
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, or an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated
    public func query(
        using check: Check,
        limitedBy: Authorizer.Limits = Authorizer.Limits.noLimits
    ) throws -> Bool {
        let resolution = try Resolution(biscuit: self, authorizer: Authorizer(limits: limitedBy))
        return try check.validate(resolution, [0], .authorizer)
    }

    /// Query the biscuit to check if a certain statement holds true
    /// - Parameter kind: What kind of check to perofrm
    /// - Parameter trusting: identities to trust when evaluating this query
    /// - Parameter limitedBy: Limitations on the runtime for this query
    /// - Parameter predicates: The predicates of this query
    /// - Returns: Whether or not the query succeeded
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, or an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated
    public func query<each T: TrustedScopeConvertible>(
        kind: Check.Kind = .checkIf,
        trusting: repeat each T,
        limitedBy: Authorizer.Limits = Authorizer.Limits.noLimits,
        @Biscuit.StatementBuilder predicates: () -> Biscuit.StatementBuilder
    ) throws -> Bool {
        var scopes: [TrustedScope] = []
        repeat scopes.append((each trusting).trustedScope)
        return try self.query(using: Check(kind: kind, trusting: scopes, predicates()), limitedBy: limitedBy)
    }

    /// Query the biscuit to check if a certain statement holds true
    /// - Parameter using: The check to use to query the biscuit, as a String
    /// - Returns: Whether or not the query succeeded
    /// - Throws: Throws an `AuthorizationError` if the biscuit does not pass authorization, or an
    /// `EvaluationError` if the biscuit or the authorizer cannot be evaluated, and parsing the
    /// Datalog may throw a `DatalogError`
    public func query(
        using datalog: String,
        limitedBy: Authorizer.Limits = Authorizer.Limits.noLimits
    ) throws -> Bool {
        try self.query(using: Check(datalog), limitedBy: limitedBy)
    }
}
