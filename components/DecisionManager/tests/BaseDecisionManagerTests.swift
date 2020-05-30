/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest

import Configuration
import Logger
import EndpointSecurityClient

final class DecisionManagerTests : XCTestCase {
    func testConfiguration() throws {
        let configuration = TestConfiguration()
        let logger = DummyLogger()
        
        var context = BaseDecisionManagerContext()
        XCTAssertFalse(context.allowInvalidPrograms)
        XCTAssertFalse(context.allowUnknownPrograms)
        XCTAssertFalse(context.allowUnsignedPrograms)


        BaseDecisionManager.readConfiguration(context: &context,
                                              configuration: configuration,
                                              logger: logger)

        XCTAssertTrue(context.allowInvalidPrograms)
        XCTAssertTrue(context.allowUnknownPrograms)
        XCTAssertTrue(context.allowUnsignedPrograms)

    }
    
    func testRequestProcessingForPlatformBinaries() throws {
        let request = DecisionManagerRequest(binaryPath: "/Applications/Safari.app",
                                             codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                           hash: "91BFCC1CE8BCE7473D35FD00BDDF33AF52A1D2FD"),

                                             signingIdentifier: "com.apple.Safari",
                                             teamIdentifier: "",
                                             platformBinary: true)
        
        let context = BaseDecisionManagerContext()
        XCTAssertFalse(context.allowInvalidPrograms)
        XCTAssertFalse(context.allowUnknownPrograms)
        XCTAssertFalse(context.allowUnsignedPrograms)

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            if signatureCheckResult == SignatureDatabaseResult.Valid {
                XCTAssertTrue(allow)
                XCTAssertTrue(cache)
            } else {
                XCTAssertFalse(allow)
                XCTAssertFalse(cache)
            }
        }
    }

    func testRequestProcessingForUnsignedPrograms() throws {
        let request = DecisionManagerRequest(binaryPath: "/Applications/Unsigned.app",
                                             codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                           hash: ""),

                                             signingIdentifier: "",
                                             teamIdentifier: "",
                                             platformBinary: false)
        
        var context = BaseDecisionManagerContext()
        XCTAssertFalse(context.allowInvalidPrograms)
        XCTAssertFalse(context.allowUnknownPrograms)
        XCTAssertFalse(context.allowUnsignedPrograms)

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            XCTAssertFalse(allow)
            XCTAssertFalse(cache)
        }

        context.allowUnsignedPrograms = true

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            if signatureCheckResult == SignatureDatabaseResult.NotSigned {
                XCTAssertTrue(allow)
            } else {
                XCTAssertFalse(allow)
            }

            XCTAssertFalse(cache)
        }
    }

    func testRequestProcessingForUnknownPrograms() throws {
        let request = DecisionManagerRequest(binaryPath: "/Applications/CMake.app",
                                             codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                           hash: "BDD0AF132D89EA4810566B3E1E0D1E48BAC6CF18"),

                                             signingIdentifier: "org.cmake.cmake",
                                             teamIdentifier: "W38PE5Y733",
                                             platformBinary: false)
        
        var context = BaseDecisionManagerContext()
        XCTAssertFalse(context.allowInvalidPrograms)
        XCTAssertFalse(context.allowUnknownPrograms)
        XCTAssertFalse(context.allowUnsignedPrograms)

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            XCTAssertFalse(allow)
            XCTAssertFalse(cache)
        }
        
        context.allowUnknownPrograms = true

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            if signatureCheckResult == SignatureDatabaseResult.Valid {
                XCTAssertTrue(allow)
            } else {
                XCTAssertFalse(allow)
            }

            XCTAssertFalse(cache)
        }
    }

    func testRequestProcessingForKnownPrograms() throws {
        let cmakeHash = "BDD0AF132D89EA4810566B3E1E0D1E48BAC6CF18"

        let request = DecisionManagerRequest(binaryPath: "/Applications/CMake.app",
                                             codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                           hash: cmakeHash),

                                             signingIdentifier: "org.cmake.cmake",
                                             teamIdentifier: "W38PE5Y733",
                                             platformBinary: false)
        
        let context = BaseDecisionManagerContext()
        XCTAssertFalse(context.allowInvalidPrograms)
        XCTAssertFalse(context.allowUnknownPrograms)
        XCTAssertFalse(context.allowUnsignedPrograms)

        var ruleDatabase = RuleDatabase()
        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: RuleDatabase(),
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            XCTAssertFalse(allow)
            XCTAssertFalse(cache)
        }

        ruleDatabase.binaryRuleMap[cmakeHash] = RuleMapEntry(ruleType: RuleType.binary,
                                                             policy: RulePolicy.whitelist,
                                                             customMessage: "Test",
                                                             truncatedHash: cmakeHash)

        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: ruleDatabase,
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            if signatureCheckResult == SignatureDatabaseResult.Valid {
                XCTAssertTrue(allow)
            } else {
                XCTAssertFalse(allow)
            }

            XCTAssertFalse(cache)
        }

        ruleDatabase.binaryRuleMap[cmakeHash]!.policy = RulePolicy.blacklist
        
        for signatureCheckResult in SignatureDatabaseResult.allCases {
            var allow = false
            var cache = false

            BaseDecisionManager.processRequest(context: context,
                                               request: request,
                                               ruleDatabase: ruleDatabase,
                                               allow: &allow,
                                               cache: &cache,
                                               signatureCheckResult: signatureCheckResult)

            XCTAssertFalse(allow)
            XCTAssertFalse(cache)
        }
    }
}

fileprivate final class TestConfiguration : ConfigurationInterface {
    func subscribe(subscriber: ConfigurationSubscriberInterface) -> Void { }

    func stringValue(section: String, key: String) -> String? {
        return nil
    }

    func integerValue(section: String, key: String) -> Int? {
        return nil
    }

    func booleanValue(section: String, key: String) -> Bool? {
        if section != "Sinter" {
            return nil
        }

        if key == "allow_unknown_programs" || key == "allow_unsigned_programs" || key == "allow_invalid_programs" {
            return true
        }

        return nil
    }
}

fileprivate final class DummyLogger : LoggerInterface {
    func setConfiguration(configuration: ConfigurationInterface) { }

    func logMessage(severity: LoggerMessageSeverity, message: String) { }
}
