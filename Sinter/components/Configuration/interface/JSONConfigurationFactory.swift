/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

public func createJSONConfiguration() -> Result<ConfigurationInterface, Error> {
    let etcFolderList: [String] = [
        "/etc",
        "/usr/local/etc",
    ]

    var configurationObjectOpt: ConfigurationInterface?

    for etcFolder in etcFolderList {
        let configFilePath = etcFolder + "/sinter/config.json"

        let jsonConfigurationExp = JSONConfiguration.create(configFilePath: configFilePath)
        switch jsonConfigurationExp {
        case let .success(obj):
            configurationObjectOpt = obj

        case let .failure(error):
            print("\(configFilePath): \(error)")
        }

        if configurationObjectOpt != nil {
            break
        }
    }

    if let configurationObject = configurationObjectOpt {
        return .success(configurationObject)

    } else {
        return .failure(ConfigurationError.notFound)
    }
}
