/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

enum OperationQueueType {
    case primary
    case secondary
}

func createOperationQueue(type: OperationQueueType) -> OperationQueue {
    let queue = OperationQueue()
    queue.qualityOfService = .userInteractive
    
    switch type {
    case .primary:
        queue.maxConcurrentOperationCount = OperationQueue.defaultMaxConcurrentOperationCount

    case .secondary:
        let onlineProcessorCount = sysconf(CInt(_SC_NPROCESSORS_ONLN))
        queue.maxConcurrentOperationCount = onlineProcessorCount
    }

    return queue
}
