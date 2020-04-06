/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public func createLocalJSONConfiguration() -> IConfiguration? {
    let etcFolderList: [String] = [
        "/etc/",
        "/usr/local/etc",
    ]

    for etcFolder in etcFolderList {
        let configPath = etcFolder + "/sinter/config.json"

        let configuration = JSONConfiguration(configFilePath: configPath)
        if configuration != nil {
            return configuration
        }
    }

    return nil
}
