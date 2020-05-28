/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration

struct BaseDecisionManagerContext {
    public var allowUnknownPrograms = false
    public var allowUnsignedPrograms = false
}

protocol RuleDatabaseProviderInterface {
    func configure(configuration: ConfigurationInterface)
    func ruleDatabase() -> RuleDatabase
}

class BaseDecisionManager: DecisionManagerInterface,
                           ConfigurationSubscriberInterface {

    private let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.base-decision-manager")
    private let logger: LoggerInterface
    private let ruleDatabaseProvider: RuleDatabaseProviderInterface

    private var context = BaseDecisionManagerContext()

    init(logger: LoggerInterface,
         configuration: ConfigurationInterface,
         ruleDatabaseProvider: RuleDatabaseProviderInterface) {

        self.logger = logger
        self.ruleDatabaseProvider = ruleDatabaseProvider
        
        configuration.subscribe(subscriber: self)
    }

    func onConfigurationChange(configuration: ConfigurationInterface) {
        BaseDecisionManager.readConfiguration(context: &context,
                                               configuration: configuration,
                                               logger: logger)

        ruleDatabaseProvider.configure(configuration: configuration)
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool) {

        BaseDecisionManager.processRequest(context: context,
                                           request: request,
                                           ruleDatabase: ruleDatabaseProvider.ruleDatabase(),
                                           allow: &allow)
    }

    static func readConfiguration(context: inout BaseDecisionManagerContext,
                                  configuration: ConfigurationInterface,
                                  logger: LoggerInterface) -> Void {

        var newAllowUnknownPrograms = false
        var newAllowUnsignedPrograms = false

        if let allowUnknownPrograms = configuration.booleanValue(section: "Sinter",
                                                                   key: "allow_unknown_programs") {
            newAllowUnknownPrograms = allowUnknownPrograms

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unknown_programs' key is missing from the Sinter section")
        }

        if let allowUnsignedPrograms = configuration.booleanValue(section: "Sinter",
                                                                   key: "allow_unsigned_programs") {
            newAllowUnsignedPrograms = allowUnsignedPrograms

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unsigned_programs' key is missing from the Sinter section")
        }
        
        context.allowUnknownPrograms = newAllowUnknownPrograms
        context.allowUnsignedPrograms = newAllowUnsignedPrograms
    }

    static func processRequest(context: BaseDecisionManagerContext,
                               request: DecisionManagerRequest,
                               ruleDatabase: RuleDatabase,
                               allow: inout Bool) -> Void {

        if request.platformBinary {
            allow = true

        } else if request.codeDirectoryHash.hash.isEmpty {
            allow = context.allowUnsignedPrograms

        } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            allow = context.allowUnknownPrograms
        }
    }
}
