/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Configuration

final class FilesystemLogger: LoggerInterface, ConfigurationSubscriberInterface {
    let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.filesystem-logger")

    func onConfigurationChange(configuration: ConfigurationInterface) { }

    func setConfiguration(configuration: ConfigurationInterface) {
        configuration.subscribe(subscriber: self)
    }

    public func logMessage(severity: LoggerMessageSeverity, message: String) {
        print("Severity: \(severity) Message: \(message)")
    }
}
