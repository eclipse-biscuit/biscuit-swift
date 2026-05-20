/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */

extension Biscuit {
    /// The result of a successful authorization check on a Biscuit
    public struct Authorization: Sendable, Hashable {
        /// Which policy statement passed, resulting in the successful authorization
        public let successfulPolicy: Policy

        let resolution: Resolution

        init(policy: Policy, resolution: Resolution) {
            self.successfulPolicy = policy
            self.resolution = resolution
        }

        /// Query the authorization to check if a certain statement holds true
        /// - Parameter check: The Check to use to query the authorization
        /// - Returns: Whether or not the query succeeded
        /// - Throws: Throws an `EvaluationError` if the query cannot be evaluated
        public func query(using check: Check) throws -> Bool {
            try check.validate(self.resolution, [0], .authorizer)
        }

        /// Query the authorization to check if a certain statement holds true
        /// - Parameter kind: What kind of check to perform
        /// - Parameter trusting: identities to trust when evaluating this query
        /// - Parameter predicates: The predicates of this query
        /// - Returns: Whether or not the query succeeded
        /// - Throws: Throws an `EvaluationError` if the query cannot be evaluated
        public func query<each T: TrustedScopeConvertible>(
            kind: Check.Kind = .checkIf,
            trusting: repeat each T,
            @Biscuit.StatementBuilder predicates: () -> Biscuit.StatementBuilder
        ) throws -> Bool {
            var scopes: [TrustedScope] = []
            repeat scopes.append((each trusting).trustedScope)
            return try self.query(using: Check(kind: kind, trusting: scopes, predicates()))
        }

        /// Query the authorization to check if a certain statement holds true
        /// - Parameter datalog: The check to use to query the authorization, as a String
        /// - Returns: Whether or not the query succeeded
        /// - Throws: Throws an `EvaluationError` if the query cannot be evaluated and parsing the
        /// Datalog may throw a `DatalogError`
        public func query(using datalog: String) throws -> Bool {
            try self.query(using: Check(datalog))
        }

        /// Query the authorization to extract values from it
        ///
        /// Some number of names and types is passed as the "result" parameter; these should be the
        /// names of variables that appear in the predicates of the query. This query will return
        /// tuples of values that satisfy the predicates when bound to those names.
        ///
        /// - Parameter result: a sequence of tuples containing the name of a variable used in the
        /// query and the type that variable is expected to be
        /// - Parameter trusting: identities to trust when evaluating this query
        /// - Parameter predicates: The predicates of this query
        /// - Returns: An array of all the tuples of values which satisfy the predicates
        /// - Throws: Throws an `EvaluationError` if the query cannot be evaluated, an
        /// `InvalidQueryError` if the query is invalid or an `InvalidValueError` if a value does
        /// not have the expected type
        public func queryValues<each V: ExpressibleByValue, each T: TrustedScopeConvertible>(
            result: repeat (String, (each V).Type),
            trusting: repeat each T,
            @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
        ) throws -> [(repeat each V)] {
            let query = try predicates()
            var scopes: [TrustedScope] = []
            repeat scopes.append((each trusting).trustedScope)
            let trusted = self.resolution.trustScopes(scopes, nil)
            let variables = try self.resolution.queryValues(query.predicates, query.expressions, trusted)
            return try variables.map { vars in
                (repeat try unpackVariable(vars, (each result).0, (each result).1))
            }
        }

        /// Query the authorization to extract values from it, expecting only one tuple of matching
        /// values.
        ///
        /// Some number of names and types is passed as the "result" parameter; these should be the
        /// names of variables that appear in the predicates of the query. This query will return
        /// tuples of values that satisfy the predicates when bound to those names.
        ///
        /// - Parameter result: a sequence of tuples containing the name of a variable used in the
        /// query and the type that variable is expected to be
        /// - Parameter trusting: identities to trust when evaluating this query
        /// - Parameter predicates: The predicates of this query
        /// - Returns: The tuples of values which satisfy the predicates
        /// - Throws: Throws an `EvaluationError` if the query cannot be evaluated, an
        /// `InvalidQueryError` if the query is invalid or returns too many or too few results, or
        /// an `InvalidValueError` if a value does not have the expected type
        public func queryValuesExpectingOne<each V: ExpressibleByValue, each T: TrustedScopeConvertible>(
            result: repeat (String, (each V).Type),
            trusting: repeat each T,
            @Biscuit.StatementBuilder predicates: () throws -> Biscuit.StatementBuilder
        ) throws -> (repeat each V) {
            let query = try predicates()
            var scopes: [TrustedScope] = []
            repeat scopes.append((each trusting).trustedScope)
            let trusted = self.resolution.trustScopes(scopes, nil)
            let variables = try self.resolution.queryValuesExpectingOne(query.predicates, query.expressions, trusted)
            return (repeat try unpackVariable(variables, (each result).0, (each result).1))
        }
    }
}

func unpackVariable<V: ExpressibleByValue>(_ vars: [String: Value], _ name: String, _ ty: V.Type) throws -> V {
    if let value = vars[name] {
        return try ty.init(value: value)
    } else {
        throw Biscuit.InvalidQueryError.missingVariable
    }
}
