/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

class Subscription {
    private weak var subscriberOpt: ConfigurationSubscriberInterface?
    private let configuration: ConfigurationInterface
    
    init(configuration: ConfigurationInterface,
         subscriber: ConfigurationSubscriberInterface) {

        self.configuration = configuration
        self.subscriberOpt = subscriber
    }
    
    func notify() -> Void {
        if let subscriber = subscriberOpt {
            subscriber.onConfigurationChange(configuration: configuration)
        }
    }
}
