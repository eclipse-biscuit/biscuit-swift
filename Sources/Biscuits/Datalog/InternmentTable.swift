/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
struct InternmentTables: Sendable, Hashable {
    var primary: BlockInternmentTable = BlockInternmentTable()
    var thirdPartyTables: [Int: BlockInternmentTable] = [:]

    subscript(index: Resolution.Scope) -> BlockInternmentTable {
        get {
            if let blockID = index.blockID {
                self.blockTable(for: blockID)
            } else {
                self.primary
            }
        }
    }

    func blockTable(for blockID: Int) -> BlockInternmentTable {
        self.thirdPartyTables[blockID] ?? self.primary
    }

    mutating func setBlockTable(_ table: BlockInternmentTable, for blockID: Int) {
        self.thirdPartyTables[blockID] = table
    }
}

struct BlockInternmentTable: Sendable, Hashable {
    var symbols: InternmentTable<String> = InternmentTable()
    var publicKeys: InternmentTable<Biscuit.ThirdPartyKey> = InternmentTable()

    mutating func extend(_ symbols: [String], _ publicKeys: [Biscuit.ThirdPartyKey]) throws {
        try self.symbols.extend(symbols, Biscuit.ValidationError.duplicateSymbol)
        try self.publicKeys.extend(publicKeys, Biscuit.ValidationError.duplicatePublicKey)
    }

    @discardableResult
    mutating func intern(_ symbol: String, _ locals: inout [String]) -> Int {
        if let idx = defaultSymbols[symbol] {
            return idx
        } else {
            return 1024 + self.symbols.intern(symbol, &locals)
        }
    }

    @discardableResult
    mutating func intern(_ publicKey: Biscuit.ThirdPartyKey, _ locals: inout [Biscuit.ThirdPartyKey]) -> Int {
        self.publicKeys.intern(publicKey, &locals)
    }

    func symbolIndex(for symbol: String) -> Int {
        defaultSymbols[symbol] ?? self.symbols.index(for: symbol) + 1024
    }

    func lookupSymbol(_ idx: Int) throws -> String {
        if idx < 1024 {
            guard idx < defaultSymbolsArray.count else {
                throw Biscuit.ValidationError.unknownSymbol
            }
            return defaultSymbolsArray[idx]
        }
        if let symbol = self.symbols.lookup(idx - 1024) {
            return symbol
        } else {
            throw Biscuit.ValidationError.unknownSymbol
        }
    }

    func publicKeyIndex(for publicKey: Biscuit.ThirdPartyKey) -> Int {
        self.publicKeys.index(for: publicKey)
    }

    func lookupPublicKey(_ idx: Int) throws -> Biscuit.ThirdPartyKey {
        if let publicKey = self.publicKeys.lookup(idx) {
            return publicKey
        } else {
            throw Biscuit.ValidationError.unknownPublicKey
        }
    }

    struct InternmentTable<T: Sendable & Hashable>: Sendable, Hashable {
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

        func lookup(_ idx: Int) -> T? {
            guard idx < self.array.count else { return nil }
            return self.array[idx]
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
