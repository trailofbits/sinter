/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

// Variable names **MUST** match the parsed JSON
private struct JSONRuleDatabaseEntry: Decodable {
    let rule_type: String
    let policy: String
    let sha256: String
    let custom_msg: String
}

private typealias JSONRuleDatabase = [String: [JSONRuleDatabaseEntry]]

enum RuleType {
    case binary
    case certificate
}

enum RulePolicy {
    case denylist
    case allowlist
}

struct RuleMapEntry {
    public var ruleType: RuleType
    public var policy: RulePolicy
    public var customMessage: String
    public var truncatedHash: String
}

typealias RuleMap = [String: RuleMapEntry]

enum RuleDatabaseStatus {
    case valid
    case partial
    case invalid
}

struct RuleDatabase {
    public var status: RuleDatabaseStatus
    public var binaryRuleMap: RuleMap
    public var certificateRuleMap: RuleMap

    public init() {
        status = RuleDatabaseStatus.valid
        binaryRuleMap = RuleMap()
        certificateRuleMap = RuleMap()
    }
}

func parseJSONRuleDatabase(jsonData: Data) -> RuleDatabase {
    var ruleDatabase = RuleDatabase()

    do {
        let jsonRuleDatabase: JSONRuleDatabase = try JSONDecoder().decode(JSONRuleDatabase.self,
                                                                          from: jsonData)

        if let jsonRuleArray = jsonRuleDatabase["rules"] {
            let validHashCharacters = CharacterSet(charactersIn: "0123456789ABCDEF")

            for jsonRule in jsonRuleArray {
                var ruleType: RuleType

                if jsonRule.rule_type == "BINARY" {
                    ruleType = RuleType.binary

                } else if jsonRule.rule_type == "CERTIFICATE" {
                    ruleType = RuleType.certificate

                } else {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                var rulePolicy: RulePolicy

                if jsonRule.policy == "ALLOWLIST" || jsonRule.policy == "WHITELIST" || jsonRule.policy == "WHITELIST_COMPILER" {
                    // WHITELIST, WHITELIST_COMPILER are supported for Google Santa compatibility
                    rulePolicy = RulePolicy.allowlist

                } else if jsonRule.policy == "DENYLIST" || jsonRule.policy == "BLACKLIST" {
                    // BLACKLIST is supported for Google Santa compatibility
                    rulePolicy = RulePolicy.denylist

                } else {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                if jsonRule.sha256.count != 64 {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                var truncatedHash = jsonRule.sha256.uppercased()

                // EndpointSecurity truncates hashes at 20 bytes, so make sure we do
                // the same
                let index = truncatedHash.index(truncatedHash.startIndex, offsetBy: 40)
                truncatedHash = String(truncatedHash[..<index])

                if truncatedHash.rangeOfCharacter(from: validHashCharacters.inverted) != nil {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                let rule = RuleMapEntry(ruleType: ruleType,
                                        policy: rulePolicy,
                                        customMessage: jsonRule.custom_msg,
                                        truncatedHash: truncatedHash)

                if ruleType == RuleType.binary {
                    ruleDatabase.binaryRuleMap[truncatedHash] = rule

                } else {
                    ruleDatabase.certificateRuleMap[truncatedHash] = rule
                }
            }
            
            if ruleDatabase.binaryRuleMap.isEmpty &&
               ruleDatabase.certificateRuleMap.isEmpty &&
               ruleDatabase.status == RuleDatabaseStatus.partial {

                ruleDatabase.status = RuleDatabaseStatus.invalid
            }

            return ruleDatabase

        } else {
            ruleDatabase.status = RuleDatabaseStatus.invalid
            return ruleDatabase
        }

    } catch {
        ruleDatabase.status = RuleDatabaseStatus.invalid
        return ruleDatabase
    }
}
