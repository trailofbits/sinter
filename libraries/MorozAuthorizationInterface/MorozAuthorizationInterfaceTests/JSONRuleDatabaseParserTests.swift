/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

@testable import MorozAuthorizationInterface
import XCTest

/*
  {
   "rules": [
     {
       "rule_type": "BINARY",
       "policy": "BLACKLIST",
       "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
       "custom_msg": "blacklist firefox"
     },
     {
       "rule_type": "CERTIFICATE",
       "policy": "BLACKLIST",
       "sha256": "e7726cf87cba9e25139465df5bd1557c8a8feed5c7dd338342d8da0959b63c8d",
       "custom_msg": "blacklist dash app certificate"
     },
     {
       "rule_type": "BINARY",
       "policy": "WHITELIST_COMPILER",
       "sha256": "60d79d1763fefb56716e4a36284300523eb4335c3726fb9070fa83074b02279e",
       "custom_msg": "whitelist go compiler component"
     },
     {
       "rule_type": "BINARY",
       "policy": "WHITELIST_COMPILER",
       "sha256": "8e78770685d51324b78588fddc6afc2f8b6cef5231c27eeb97363cc437fec18a",
       "custom_msg": "whitelist go compiler component"
     },
     {
       "rule_type": "BINARY",
       "policy": "WHITELIST_COMPILER",
       "sha256": "e88617cfd62809fb10e213c459a52f48e028fae4321e41134c4797465af886b6",
       "custom_msg": "whitelist go compiler component"
     },
     {
       "rule_type": "BINARY",
       "policy": "WHITELIST_COMPILER",
       "sha256": "d867fca68bbd7db18e9ced231800e7535bc067852b1e530987bb7f57b5e3a02c",
       "custom_msg": "whitelist go compiler component"
     }
   ]
 }
 */

class JSONRuleDatabaseParserTests: XCTestCase {
    let emptyFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    let expectedRuleMessage = "Test message"

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testBinaryBlacklistRule() throws {
        let binaryBlacklistRule = """
        {
         "rules": [
           {
             "rule_type": "BINARY",
             "policy": "BLACKLIST",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: binaryBlacklistRule.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.binaryRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.binary)
        XCTAssertEqual(rule.policy, RulePolicy.blacklist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testBinaryWhitelistRule1() throws {
        let binaryWhitelistRule1 = """
        {
         "rules": [
           {
             "rule_type": "BINARY",
             "policy": "WHITELIST",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: binaryWhitelistRule1.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.binaryRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.binary)
        XCTAssertEqual(rule.policy, RulePolicy.whitelist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testBinaryWhitelistRule2() throws {
        let binaryWhitelistRule2 = """
        {
         "rules": [
           {
             "rule_type": "BINARY",
             "policy": "WHITELIST_COMPILER",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: binaryWhitelistRule2.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.binaryRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.binary)
        XCTAssertEqual(rule.policy, RulePolicy.whitelist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testCertificateBlacklistRule() throws {
        let certificateBlacklistRule = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "BLACKLIST",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: certificateBlacklistRule.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.certificateRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.certificate)
        XCTAssertEqual(rule.policy, RulePolicy.blacklist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testCertificateWhitelistRule1() throws {
        let certificateWhitelistRule1 = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "WHITELIST",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: certificateWhitelistRule1.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.certificateRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.certificate)
        XCTAssertEqual(rule.policy, RulePolicy.whitelist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testCertificateWhitelistRule2() throws {
        let certificateWhitelistRule2 = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "WHITELIST_COMPILER",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: certificateWhitelistRule2.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 1)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)

        let ruleOpt = ruleDatabase.certificateRuleMap[emptyFileHash]
        XCTAssertNotNil(ruleOpt)

        let rule = ruleOpt!
        XCTAssertEqual(rule.ruleType, RuleType.certificate)
        XCTAssertEqual(rule.policy, RulePolicy.whitelist)
        XCTAssertEqual(rule.sha256, emptyFileHash)
        XCTAssertEqual(rule.customMessage, expectedRuleMessage)
    }

    func testInvalidRule1() throws {
        let invalidRule1 = """
        {
         "rules": [
           {
             "rule_type": "X",
             "policy": "WHITELIST_COMPILER",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidRule1.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.partial)
    }

    func testInvalidRule2() throws {
        let invalidRule2 = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "x",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidRule2.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.partial)
    }

    func testInvalidRule3() throws {
        let invalidRule3 = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "WHITELIST",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb9",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidRule3.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.partial)
    }

    func testInvalidRule4() throws {
        let invalidRule4 = """
        {
         "rules": [
           {
             "rule_type": "CERTIFICATE",
             "policy": "WHITELIST",
             "sha256": "K3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "custom_msg": "Test message"
           },
         ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidRule4.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.partial)
    }

    func testEmptyRuleDatabase() throws {
        let emptyValid1 = """
        {
         "rules": [ ]
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: emptyValid1.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.valid)
    }

    func testInvalidRuleDatabase() throws {
        let emptyInvalid2 = """
        {
        }
        """

        let ruleDatabase = parseJSONRuleDatabase(jsonData: emptyInvalid2.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)
    }

    func testInvalidJSON1() throws {
        let invalidJson1 = ""

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidJson1.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)
    }

    func testInvalidJSON2() throws {
        let invalidJson2 = "x"

        let ruleDatabase = parseJSONRuleDatabase(jsonData: invalidJson2.data(using: .utf8)!)
        XCTAssertEqual(ruleDatabase.binaryRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.certificateRuleMap.count, 0)
        XCTAssertEqual(ruleDatabase.status, RuleDatabaseStatus.invalid)
    }
}
