/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

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
    case blacklist
    case whitelist
}

struct RuleMapEntry {
    public var ruleType: RuleType
    public var policy: RulePolicy
    public var customMessage: String
    public var sha256: String
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

                if jsonRule.policy == "WHITELIST" || jsonRule.policy == "WHITELIST_COMPILER" {
                    rulePolicy = RulePolicy.whitelist

                } else if jsonRule.policy == "BLACKLIST" {
                    rulePolicy = RulePolicy.blacklist

                } else {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                if jsonRule.sha256.count != 64 {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                let sha256 = jsonRule.sha256.uppercased()

                if sha256.rangeOfCharacter(from: validHashCharacters.inverted) != nil {
                    ruleDatabase.status = RuleDatabaseStatus.partial
                    continue
                }

                let rule = RuleMapEntry(ruleType: ruleType,
                                        policy: rulePolicy,
                                        customMessage: jsonRule.custom_msg,
                                        sha256: sha256)

                // TODO: We are truncating this to 20 chars because EndpointSecurity truncates
                //      the hash too. We need to add support for getting the full hash from the
                //      binary
                let index = sha256.index(sha256.startIndex, offsetBy: 40)
                let truncatedHash = String(sha256[..<index])

                if ruleType == RuleType.binary {
                    ruleDatabase.binaryRuleMap[sha256] = rule
                    ruleDatabase.binaryRuleMap[truncatedHash] = rule

                } else {
                    ruleDatabase.certificateRuleMap[sha256] = rule
                    ruleDatabase.certificateRuleMap[truncatedHash] = rule
                }
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
