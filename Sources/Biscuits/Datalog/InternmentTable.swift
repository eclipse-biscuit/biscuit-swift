/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */

struct InternmentTable: Sendable, Hashable {
    var symbols: InternmentTableInner<String> = InternmentTableInner()
    var publicKeys: InternmentTableInner<Biscuit.ThirdPartyKey> = InternmentTableInner()

    mutating func extend(_ symbols: [String], _ publicKeys: [Biscuit.ThirdPartyKey]) throws {
        try self.symbols.extend(symbols, Biscuit.ValidationError.duplicateSymbol)
        try self.publicKeys.extend(publicKeys, Biscuit.ValidationError.duplicatePublicKey)
    }

    mutating func intern(_ symbol: String, _ locals: inout [String]) -> Int {
        if let idx = defaultSymbols[symbol] {
            return idx
        } else {
            return 1024 + self.symbols.intern(symbol, &locals)
        }
    }

    mutating func intern(_ publicKey: Biscuit.ThirdPartyKey, _ locals: inout [Biscuit.ThirdPartyKey]) -> Int {
        self.publicKeys.intern(publicKey, &locals)
    }

    func symbolIndex(for symbol: String) -> Int {
        defaultSymbols[symbol] ?? self.symbols.index(for: symbol) + 1024
    }

    func lookupSymbol<Index: BinaryInteger>(_ idx: Index) throws -> String {
        let idx = try idx.validatedIndex()
        if idx < 1024 {
            return try defaultSymbolsArray.element(at: idx)
        }
        return try self.symbols.lookup(idx - 1024)
    }

    func publicKeyIndex(for publicKey: Biscuit.ThirdPartyKey) -> Int {
        self.publicKeys.index(for: publicKey)
    }

    func lookupPublicKey<Index: BinaryInteger>(_ idx: Index) throws -> Biscuit.ThirdPartyKey {
        try self.publicKeys.lookup(idx.validatedIndex())
    }

    struct InternmentTableInner<T: Sendable & Hashable>: Sendable, Hashable {
        var table: [T: Int] = [:]
        var array: [T] = []

        mutating func intern(_ value: T, _ locals: inout [T]) -> Int {
            if let idx = self.table[value] {
                return idx
            } else {
                let idx = self.array.count
                self.table[value] = idx
                self.array.append(value)
                locals.append(value)
                return idx
            }
        }

        mutating func extend(_ values: [T], _ err: Biscuit.ValidationError) throws {
            for value in values {
                if self.table[value] != nil {
                    throw err
                }
                self.table[value] = self.array.count
                self.array.append(value)
            }
        }

        func index(for value: T) -> Int {
            self.table[value]!
        }

        func lookup(_ idx: Int) throws -> T {
            try self.array.element(at: idx)
        }
    }
}

let defaultSymbols: [String: Int] = [
    "read": 0,
    "write": 1,
    "resource": 2,
    "operation": 3,
    "right": 4,
    "time": 5,
    "role": 6,
    "owner": 7,
    "tenant": 8,
    "namespace": 9,
    "user": 10,
    "team": 11,
    "service": 12,
    "admin": 13,
    "email": 14,
    "group": 15,
    "member": 16,
    "ip_address": 17,
    "client": 18,
    "client_ip": 19,
    "domain": 20,
    "path": 21,
    "version": 22,
    "cluster": 23,
    "node": 24,
    "hostname": 25,
    "nonce": 26,
    "query": 27,
]

let defaultSymbolsArray: [String] = [
    "read",
    "write",
    "resource",
    "operation",
    "right",
    "time",
    "role",
    "owner",
    "tenant",
    "namespace",
    "user",
    "team",
    "service",
    "admin",
    "email",
    "group",
    "member",
    "ip_address",
    "client",
    "client_ip",
    "domain",
    "path",
    "version",
    "cluster",
    "node",
    "hostname",
    "nonce",
    "query",
]
