/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration

class LocalRuleDatabaseProvider : RuleDatabaseProviderInterface {
    private let logger: LoggerInterface
    
    init(logger: LoggerInterface) {
        self.logger = logger
    }

    func getRuleDatabase(configuration: ConfigurationInterface) -> RuleDatabase? {
        if let ruleDatabasePath = configuration.stringValue(section: "LocalDecisionManager",
                                                            key: "rule_database_path") {

            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: ruleDatabasePath) {
                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "The rule database file does not exist: \(ruleDatabasePath)")

                return nil
            }

            let ruleDatabaseURL = URL(fileURLWithPath: ruleDatabasePath)

            do {
                let jsonRuleDatabase = try Data(contentsOf: ruleDatabaseURL)
                let newRuleDatabase = parseJSONRuleDatabase(jsonData: jsonRuleDatabase)

                var acceptRules = false
                switch newRuleDatabase.status {
                case RuleDatabaseStatus.invalid:
                    logger.logMessage(severity: LoggerMessageSeverity.error,
                                      message: "The rule database is not valid")

                case RuleDatabaseStatus.partial:
                    acceptRules = true

                    logger.logMessage(severity: LoggerMessageSeverity.error,
                                      message: "The rule database contains invalid rules")

                case RuleDatabaseStatus.valid:
                    acceptRules = true
                }

                if !acceptRules {
                    return nil
                }

                return newRuleDatabase

            } catch {
                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "The rule database file is not valid")

                return nil
            }

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unknown_programs' key is missing from the Sinter section")
            
            return nil
        }
    }
}
