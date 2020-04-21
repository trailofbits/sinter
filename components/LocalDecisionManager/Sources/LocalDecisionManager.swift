/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import LibSinter
import NotificationService

private enum DefaultAction {
    case allow
    case deny
    case userPrompt
}

private final class LocalDecisionManager: DecisionManagerInterface {
    private let logger: LoggerInterface
    private let configuration: ConfigurationInterface

    private let defaultAction: DefaultAction
    private let ruleDatabasePath: String

    private var ruleDatabase = RuleDatabase()
    private var ruleDatabaseUpdateTimer = Timer()

    private let notificationClient = createNotificationClient()

    private init(logger: LoggerInterface,
                 configuration: ConfigurationInterface) throws {
        self.logger = logger
        self.configuration = configuration

        var configUpdateIntervalOpt = configuration.integerValue(moduleName: "LocalDecisionManager",
                                                                 key: "update_interval")

        if configUpdateIntervalOpt == nil {
            configUpdateIntervalOpt = 60
        }

        if let ruleDatabasePath = configuration.stringValue(moduleName: "LocalDecisionManager",
                                                            key: "rule_database_path") {
            self.ruleDatabasePath = ruleDatabasePath

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'rule_database_path' setting is missing from the 'LocalDecisionManager' configuration section")

            throw DecisionManagerError.invalidConfiguration
        }

        if let defaultAction = configuration.stringValue(moduleName: "LocalDecisionManager",
                                                         key: "default_action") {
            if defaultAction == "allow" {
                self.defaultAction = DefaultAction.allow

            } else if defaultAction == "deny" {
                self.defaultAction = DefaultAction.deny

            } else if defaultAction == "userPrompt" {
                self.defaultAction = DefaultAction.userPrompt

            } else {
                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "The 'LocalDecisionManager.default_action' setting is not valid. Allowed values are: 'allow', 'deny', 'userPrompt'")

                throw DecisionManagerError.invalidConfiguration
            }

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'default_action' setting is missing from the 'LocalDecisionManager' configuration section")

            throw DecisionManagerError.invalidConfiguration
        }

        ruleDatabaseUpdateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(configUpdateIntervalOpt!),
                                                       repeats: true) { _ in self.updateRuleDatabase() }

        ruleDatabaseUpdateTimer.fire()
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool) -> Bool {
        if request.platformBinary {
            allow = true

        } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            switch defaultAction {
            case .allow:
                allow = true

            case .deny:
                allow = false

            case .userPrompt:
                notificationClient.requestAuthorization(binaryPath: request.binaryPath,
                                                        hash: request.codeDirectoryHash.hash,
                                                        allowExecution: &allow)
            }
        }

        return true
    }

    static func create(logger: LoggerInterface,
                       configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
        Result<DecisionManagerInterface, Error> { try LocalDecisionManager(logger: logger,
                                                                           configuration: configuration) }
    }

    private func updateRuleDatabase() {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Updating rule database from \(ruleDatabasePath)...")

        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: ruleDatabasePath) {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The rule database file file does not exist")

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
