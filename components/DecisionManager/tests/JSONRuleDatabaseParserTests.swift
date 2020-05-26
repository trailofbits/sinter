/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest

final class JSONRuleDatabaseParserTests : XCTestCase {
    func parseJsonString(json: String) -> RuleDatabase {
        let jsonDataOpt = json.data(using: .utf8)
        XCTAssertNotNil(jsonDataOpt)

        let jsonData = jsonDataOpt!
        return parseJSONRuleDatabase(jsonData: jsonData)
    }

    func testValidDatabase() throws {
        let validRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" }, { \"rule_type\": \"CERTIFICATE\", \"policy\": \"BLACKLIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test2\" } ] }"

        let truncatedHash = "4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5"

        let ruleDatabase = parseJsonString(json: validRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 1)

        let binaryRuleIteratorOpt = ruleDatabase.binaryRuleMap.first
        XCTAssertNotNil(binaryRuleIteratorOpt)
        
        let binaryRuleIterator = binaryRuleIteratorOpt!
        XCTAssertEqual(binaryRuleIterator.key, truncatedHash)
        
        let binaryRule = binaryRuleIterator.value
        XCTAssertEqual(binaryRule.truncatedHash, truncatedHash)
        XCTAssertEqual(binaryRule.policy, RulePolicy.whitelist)
        XCTAssertEqual(binaryRule.ruleType, RuleType.binary)
        XCTAssertEqual(binaryRule.customMessage, "Test1")

        let certificateRuleIteratorOpt = ruleDatabase.certificateRuleMap.first
        XCTAssertNotNil(certificateRuleIteratorOpt)
        
        let certificateRuleIterator = certificateRuleIteratorOpt!
        XCTAssertEqual(certificateRuleIterator.key, truncatedHash)
        
        let certificateRule = certificateRuleIterator.value
        XCTAssertEqual(certificateRule.truncatedHash, truncatedHash)
        XCTAssertEqual(certificateRule.policy, RulePolicy.blacklist)
        XCTAssertEqual(certificateRule.ruleType, RuleType.certificate)
        XCTAssertEqual(certificateRule.customMessage, "Test2")
    }

    func testEmptyDatabase() throws {
        let validRuleDatabase = "{ \"rules\": [ ] }"

        let ruleDatabase = parseJsonString(json: validRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testPartialDatabase() throws {
        let partialRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" }, { \"rule_type\": \"test\", \"policy\": \"test\", \"sha256\": \"test\", \"custom_msg\": \"test\" } ] }"

        let ruleDatabase = parseJsonString(json: partialRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.partial)

        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 1)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testInvalidDatabase() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" }, { \"test\": \"test\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testBrokenDatabase() throws {
        let invalidRuleDatabase = "{ }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testInvalidRuleType() throws {
        let validRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"test\", \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: validRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testInvalidPolicyType() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"test\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testInvalidHash() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"sha256\": \"test\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testMissingRuleType() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testMissingPolicyType() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testMissingHash() throws {
        let invalidRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"custom_msg\": \"Test1\" } ] }"

        let ruleDatabase = parseJsonString(json: invalidRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }

    func testMissingCustomMessage() throws {
        let validRuleDatabase = "{ \"rules\": [ { \"rule_type\": \"BINARY\", \"policy\": \"WHITELIST\", \"sha256\": \"4FC009DCC8B6B11FBFFB47051AA26BC9CE6C24F5FD8EA69380CFBE534FF9860A\" } ] }"

        let ruleDatabase = parseJsonString(json: validRuleDatabase)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)

        XCTAssertTrue(ruleDatabase.binaryRuleMap.isEmpty)
        XCTAssertTrue(ruleDatabase.certificateRuleMap.isEmpty)
    }
}
