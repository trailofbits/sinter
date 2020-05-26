/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager
import Logger
import Configuration

private final class LocalDecisionManager: DecisionManagerInterface {
    private let logger: LoggerInterface
    private let configurationSource: ConfigurationInterface
    private var configuration: Configuration

    private var configUpdateTimer = Timer()

    private var ruleDatabase = RuleDatabase()

    private init(logger: LoggerInterface,
                 configurationSource: ConfigurationInterface) throws {

        self.logger = logger
        self.configurationSource = configurationSource

        // Make sure that at least the very first configuration succeeds, since we
        // always revert to the last known good configuration if the the file breaks
        // later on when we do an update
        if let configuration = LocalDecisionManager.readConfiguration(configurationSource: self.configurationSource,
                                                                      logger: self.logger) {
            self.configuration = configuration
        } else {
            throw DecisionManagerError.invalidConfiguration
        }

        self.updateRuleDatabase()

        configUpdateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(self.configuration.configurationUpdateInterval()),
                                                 repeats: true) { _ in
                                                    if let newConfiguration = LocalDecisionManager.readConfiguration(configurationSource: self.configurationSource, logger: self.logger) {
                                                        self.configuration = newConfiguration
                                                    }

                                                    self.updateRuleDatabase()
                                                }
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool) -> Bool {
        if request.platformBinary {
            allow = true

        } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            allow = self.configuration.unknownProgramsAllowed()
        }

        return true
    }

    static func create(logger: LoggerInterface,
                       configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
        Result<DecisionManagerInterface, Error> { try LocalDecisionManager(logger: logger,
                                                                           configurationSource: configuration) }
    }

    private static func readConfiguration(configurationSource: ConfigurationInterface,
                                          logger: LoggerInterface) -> Configuration? {

        do {
            return try Configuration(configurationSource: configurationSource)

        } catch ConfigurationError.invalidRuleDatabasePathKey {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'rule_database_path' key is missing from the LocalDecisionManager section")

            return nil

        } catch ConfigurationError.invalidOrMissingAllowUnknownProgramsKey {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unknown_programs' key is missing from the LocalDecisionManager section")

            return nil

        } catch {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                               message: "Unexpected error occurred when attempting to acquire the LocalDecisionManager configuration")

            return nil
        }
    }

    private func updateRuleDatabase() {
        let ruleDatabasePath = self.configuration.databasePath()

        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Updating rule database from \(ruleDatabasePath)...")

        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: ruleDatabasePath) {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The rule database file does not exist")

            return
        }

        let databaseFileURL = URL(fileURLWithPath: ruleDatabasePath)
        var newRuleDatabase = RuleDatabase()

        do {
            let jsonData = try Data(contentsOf: databaseFileURL)
            newRuleDatabase = parseJSONRuleDatabase(jsonData: jsonData)

        } catch {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The rule database file is not valid")

            return
        }

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

        if acceptRules {
            ruleDatabase = newRuleDatabase
        }
    }
}

public func createLocalDecisionManager(logger: LoggerInterface,
                                       configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
    LocalDecisionManager.create(logger: logger,
                                configuration: configuration)
}
