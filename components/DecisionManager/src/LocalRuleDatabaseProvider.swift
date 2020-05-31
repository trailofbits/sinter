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
    
    private let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.local-rule-database-provider")
    private var database = RuleDatabase()
    
    init(logger: LoggerInterface) {
        self.logger = logger
    }
    
    func configure(configuration: ConfigurationInterface) {
        let ruleDatabasePathOpt = configuration.stringValue(section: "LocalDecisionManager",
                                                            key: "rule_database_path")
        
        if ruleDatabasePathOpt == nil {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'rule_database_path' key is missing from the LocalDecisionManager section")
            
            return
        }

        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: ruleDatabasePathOpt!) {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The rule database file does not exist: \(ruleDatabasePathOpt!)")

            return
        }

        let ruleDatabaseURL = URL(fileURLWithPath: ruleDatabasePathOpt!)
        let jsonRuleDatabase: Data

        do {
            jsonRuleDatabase = try Data(contentsOf: ruleDatabaseURL)

        } catch {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The rule database file is not valid")
            
            return
        }

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
            return
        }

        dispatchQueue.sync {
            self.database = newRuleDatabase
        }
    }

    func ruleDatabase() -> RuleDatabase {
        var ruleDatabase = RuleDatabase()
        
        dispatchQueue.sync {
            ruleDatabase = self.database
        }
        
        return ruleDatabase
    }
}
