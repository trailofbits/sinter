/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration
import EndpointSecurityClient

struct BaseDecisionManagerContext {
    public var allowUnknownPrograms = false
    public var allowUnsignedPrograms = false
    public var allowInvalidPrograms = false
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
        dispatchQueue.sync {
            BaseDecisionManager.readConfiguration(context: &context,
                                                  configuration: configuration,
                                                  logger: logger)

            ruleDatabaseProvider.configure(configuration: configuration)
        }
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool,
                               cache: inout Bool,
                               signatureCheckResult: SignatureDatabaseResult) {

        BaseDecisionManager.processRequest(context: context,
                                           request: request,
                                           ruleDatabase: ruleDatabaseProvider.ruleDatabase(),
                                           allow: &allow,
                                           cache: &cache,
                                           signatureCheckResult: signatureCheckResult)
    }

    static func readConfiguration(context: inout BaseDecisionManagerContext,
                                  configuration: ConfigurationInterface,
                                  logger: LoggerInterface) -> Void {

        var newAllowUnknownPrograms = false
        var newAllowUnsignedPrograms = false
        var newAllowInvalidPrograms = false

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

        if let allowInvalidPrograms = configuration.booleanValue(section: "Sinter",
                                                                 key: "allow_invalid_programs") {
            newAllowInvalidPrograms = allowInvalidPrograms

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_invalid_programs' key is missing from the Sinter section")
        }
        
        context.allowUnknownPrograms = newAllowUnknownPrograms
        context.allowUnsignedPrograms = newAllowUnsignedPrograms
        context.allowInvalidPrograms = newAllowInvalidPrograms
    }

    static func processRequest(context: BaseDecisionManagerContext,
                               request: DecisionManagerRequest,
                               ruleDatabase: RuleDatabase,
                               allow: inout Bool,
                               cache: inout Bool,
                               signatureCheckResult: SignatureDatabaseResult) -> Void {

        cache = false

        switch signatureCheckResult {
        case SignatureDatabaseResult.Failed:
            allow = context.allowInvalidPrograms

        case SignatureDatabaseResult.Invalid:
            allow = context.allowInvalidPrograms

        case SignatureDatabaseResult.NotSigned:
            allow = context.allowUnsignedPrograms

        case SignatureDatabaseResult.Valid:
            if request.binaryType == BinaryType.platform ||
               request.binaryType == BinaryType.sinter {

                allow = true
                cache = true

            } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
                allow = rule.policy == RulePolicy.whitelist

            } else {
                allow = context.allowUnknownPrograms
            }
        }
    }
}
