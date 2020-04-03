/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

final class FilesystemLogger: ILogger {
    private let path: String

    public init?(logFolderPath: String) {
        // TODO: generate a file path and then create a new log
        path = logFolderPath
    }

    public func logAuthorization(message: AuthorizationLogMessage) {
        // TODO: write to file
        if message.allowed {
            print("Allowed:", message.binaryPath)
        } else {
            print("Denied:", message.binaryPath)
        }
    }

    public func logMessage(severity _: LogMessageSeverity, message: String) {
        // TODO: write to file
        print("Message:", message)
    }
}
