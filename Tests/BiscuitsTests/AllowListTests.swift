/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
import XCTest

@testable import Biscuits

final class AllowListTests: XCTestCase {
    // Every setting must be at its most restrictive value in allowNothing, including settings added
    // in the future, so this checks each stored property by reflection rather than by name
    func testAllowNothingAllowsNothing() {
        assertAllowsNothing(Biscuit.AllowList.allowNothing, path: "allowNothing")
    }

    func testPerBlockAllowNothingAllowsNothing() {
        assertAllowsNothing(Biscuit.AllowList.PerBlock.allowNothing, path: "PerBlock.allowNothing")
    }

    private func assertAllowsNothing(_ value: Any, path: String) {
        let children = Mirror(reflecting: value).children
        XCTAssertFalse(children.isEmpty, "\(path) has no fields to check")
        for child in children {
            let label = child.label ?? "?"
            let path = "\(path).\(label)"
            let mirror = Mirror(reflecting: child.value)
            switch child.value {
            case let flag as Bool:
                XCTAssertFalse(flag, "\(path) should be false")
            case let limit as Int where label == "minimumSignatureVersion":
                XCTAssertEqual(limit, 1, "\(path) should be the highest supported version")
            case let limit as Int:
                XCTAssertEqual(limit, 0, "\(path) should be 0")
            case _ where mirror.displayStyle == .optional:
                // Every optional setting is a set, where nil would allow anything
                guard let set = mirror.children.first?.value else {
                    XCTFail("\(path) should be an empty set, not nil")
                    continue
                }
                let setMirror = Mirror(reflecting: set)
                XCTAssertEqual(setMirror.displayStyle, .set, "\(path) is an unexpected optional type")
                XCTAssertTrue(setMirror.children.isEmpty, "\(path) should be empty")
            case _ where mirror.displayStyle == .struct:
                assertAllowsNothing(child.value, path: path)
            default:
                XCTFail("\(path) has a type this test doesn't know how to check")
            }
        }
    }
}
