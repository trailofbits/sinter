/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Configuration
import Foundation

public func createFilesystemLogger(configuration: IConfiguration) -> ILogger? {
    if let logFolderPath = configuration.stringValue(moduleName: "FilesystemLogger", key: "log_folder") {
        return FilesystemLogger(logFolderPath: logFolderPath)

    } else {
        print("Failed to locate the following configuration key: FilesystemLogger.log_folder")
        return nil
    }
}
