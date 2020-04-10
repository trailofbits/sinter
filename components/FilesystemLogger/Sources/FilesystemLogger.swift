/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import LibSinter

private final class FilesystemLogger: LoggerInterface {
    let logFolder: String

    private init(configuration _: ConfigurationInterface) throws {
        logFolder = "/var/log/sinter"
    }

    static func create(configuration: ConfigurationInterface) -> Result<LoggerInterface, Error> {
        Result<LoggerInterface, Error> { try FilesystemLogger(configuration: configuration) }
    }

    public func logMessage(severity: LoggerMessageSeverity, message: String) {
        print("Severity: \(severity) Message: \(message)")
    }
}

public func createFilesystemLogger(configuration: ConfigurationInterface) -> Result<LoggerInterface, Error> {
    FilesystemLogger.create(configuration: configuration)
}
