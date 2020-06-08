/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Configuration
import Foundation
import OSLog

final class UnifiedLogging : LoggerInterface, ConfigurationSubscriberInterface {
    let messageLogger = OSLog(subsystem: "com.trailofbits.sinter", category: "message")

    func setConfiguration(configuration: ConfigurationInterface) { }
    func onConfigurationChange(configuration: ConfigurationInterface) { }
    
    func logMessage(severity: LoggerMessageSeverity, message: String) {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MMM-dd HH:mm:ss"

        let timestamp = dateFormatter.string(from: Date())
        let message = String(format: "{ \"timestamp\": \"\(timestamp)\", \"type\": \"message\", \"severity\": \"\(severity)\", \"message\": \"\(message)\" }\n")

        var messageType: OSLogType
        switch severity {
        case LoggerMessageSeverity.debug:
            messageType = OSLogType.debug

        case LoggerMessageSeverity.information:
            messageType = OSLogType.info

        case LoggerMessageSeverity.warning:
            messageType = OSLogType.error

        case LoggerMessageSeverity.error:
            messageType = OSLogType.error
        }

        os_log("%{public}@?", log: messageLogger, type: messageType, message)
    }
}
