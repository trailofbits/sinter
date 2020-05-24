/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest

@testable import JSONConfiguration
import AuthorizationManager

fileprivate final class JSONConfigurationTests: XCTestCase {
    let validConfiguration = "{ \"Section\": { \"string\": \"string\", \"integer\": 1, \"boolean\": \"true\" } }"

    private func loadConfiguration(context: inout JSONConfigurationContext,
                                   config: String) -> ConfigurationError? {

        context = JSONConfigurationContext()

        if let buffer = config.data(using: .utf8) {
            var newContext = JSONConfigurationContext()
            if let error = JSONConfiguration.loadConfigurationFromBuffer(context: &newContext,
                                                                         configFilePath: "/etc/sinter/config.json",
                                                                         buffer: buffer) {
                return error
            }

            context = newContext
            return nil
            
        } else {
            return ConfigurationError.invalidFormat
        }
    }

    func testValidConfiguration() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let stringValueOpt = JSONConfiguration.stringValue(context: context,
                                                           moduleName: "Section",
                                                           key: "string")

        XCTAssertNotNil(stringValueOpt)
        XCTAssertEqual(stringValueOpt!, "string")

        let integerValueOpt = JSONConfiguration.integerValue(context: context,
                                                             moduleName: "Section",
                                                             key: "integer")

        XCTAssertNotNil(integerValueOpt)
        XCTAssertEqual(integerValueOpt!, 1)

        let booleanValueOpt = JSONConfiguration.booleanValue(context: context,
                                                             moduleName: "Section",
                                                             key: "boolean")

        XCTAssertNotNil(booleanValueOpt)
        XCTAssertEqual(booleanValueOpt!, true)
    }

    func testMissingSection() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let stringValueOpt = JSONConfiguration.stringValue(context: context,
                                                           moduleName: "MissingSection",
                                                           key: "string")

        XCTAssertNil(stringValueOpt)
    }

    func testMissingValue() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let stringValueOpt = JSONConfiguration.stringValue(context: context,
                                                           moduleName: "Section",
                                                           key: "missingKey")

        XCTAssertNil(stringValueOpt)
    }

    func testInvalidConfiguration() {
        let invalidConfiguration = "{ test }"

        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: invalidConfiguration)

        XCTAssertNotNil(errorOpt)
        XCTAssertEqual(errorOpt!, ConfigurationError.invalidFormat)
    }

    func testInvalidInteger() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let integerValueOpt = JSONConfiguration.integerValue(context: context,
                                                             moduleName: "Section",
                                                             key: "string")

        XCTAssertNil(integerValueOpt)
    }

    func testInvalidBoolean() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let booleanValueOpt = JSONConfiguration.booleanValue(context: context,
                                                             moduleName: "Section",
                                                             key: "string")

        XCTAssertNil(booleanValueOpt)
    }

    func testInvalidString() {
        var context = JSONConfigurationContext()
        let errorOpt = loadConfiguration(context: &context,
                                         config: validConfiguration)

        XCTAssertNil(errorOpt)

        let stringValueOpt = JSONConfiguration.booleanValue(context: context,
                                                             moduleName: "Section",
                                                             key: "integer")

        XCTAssertNil(stringValueOpt)
    }

    func testInvalidFilePath() {
        let invalidPath = "/this/field/does/not/exists"

        var context = JSONConfigurationContext()
        let errorOpt = JSONConfiguration.loadConfigurationFromFile(context: &context,
                                                                   configFilePath: invalidPath)

        XCTAssertNotNil(errorOpt)
        XCTAssertEqual(errorOpt!, ConfigurationError.notFound)
    }
}
