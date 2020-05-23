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
    
    switch type {
    case .primary:
        let onlineProcessorCount = sysconf(CInt(_SC_NPROCESSORS_ONLN))

        queue.maxConcurrentOperationCount = onlineProcessorCount
        queue.qualityOfService = .userInteractive

    case .secondary:
        queue.maxConcurrentOperationCount = 1
        queue.qualityOfService = .background
    }

    return queue
}

struct FileInformation {
    public var ownerId: Int = 0
    public var size: Int = 0
}

func getFileInformation(path: String) -> FileInformation? {
    let fileAttributes: [FileAttributeKey : Any]

    do {
        fileAttributes = try FileManager.default.attributesOfItem(atPath: path)
    } catch {
        return nil
    }
    
    var fileInformation = FileInformation()

    if let fileSize = fileAttributes[FileAttributeKey.size] as? Int {
        fileInformation.size = fileSize
    } else {
        return nil
    }

    if let ownerId = fileAttributes[FileAttributeKey.ownerAccountID] as? Int {
        fileInformation.ownerId = ownerId
    } else {
        return nil
    }
    
    return fileInformation
}
