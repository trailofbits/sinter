/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest
import EndpointSecurityClient
import DecisionManager
import Logger
import Configuration

@testable import AuthorizationManager

fileprivate final class MockedLogger : LoggerInterface {
    func setConfiguration(configuration: ConfigurationInterface) { }
    func logMessage(severity: LoggerMessageSeverity, message: String) { }
}

class SignatureDatabaseTests: XCTestCase {
    private func generateContext() -> SignatureDatabaseContext {
        let context = SignatureDatabaseContext()

        context.resultCache["/Applications/Safari.app"] = SignatureDatabaseResult.Valid
        context.resultCache["/Applications/CMake.app"] = SignatureDatabaseResult.Invalid
        context.resultCache["/Applications/iTerm.app"] = SignatureDatabaseResult.Failed

        var testPath = "/Applications/Xcode.app"
        context.operationMap[testPath] = SignatureDatabaseOperation(path: testPath,
                                                                    cachedResultOpt: nil)

        testPath = "/Applications/Google Chrome.app"
        context.operationMap[testPath] = SignatureDatabaseOperation(path: testPath,
                                                                    cachedResultOpt: nil)

        return context
    }

    func testFullCacheInvalidation() throws {
        var context = generateContext()
        XCTAssertEqual(context.resultCache.count, 3)
        XCTAssertEqual(context.operationMap.count, 2)
        
        SignatureDatabase.invalidateCache(context: &context)
        XCTAssertTrue(context.resultCache.isEmpty)
        XCTAssertTrue(context.operationMap.isEmpty)
    }

    func testPathBasedCacheInvalidation() throws {
        var context = generateContext()
        XCTAssertEqual(context.resultCache.count, 3)
        XCTAssertEqual(context.operationMap.count, 2)
        
        let mockedLogger = MockedLogger()
        SignatureDatabase.invalidateCacheFor(context: &context,
                                             path: "/Applications/Safari.app/Contents/Info.plist",
                                             logger: mockedLogger)

        XCTAssertEqual(context.resultCache.count, 2)
        XCTAssertEqual(context.operationMap.count, 2)

        SignatureDatabase.invalidateCacheFor(context: &context,
                                             path: "/Applications/Test.app",
                                             logger: mockedLogger)

        XCTAssertEqual(context.resultCache.count, 2)
        XCTAssertEqual(context.operationMap.count, 2)

        SignatureDatabase.invalidateCacheFor(context: &context,
                                             path: "/Applications/CMake.app",
                                             logger: mockedLogger)

        XCTAssertEqual(context.resultCache.count, 1)
        XCTAssertEqual(context.operationMap.count, 2)

        SignatureDatabase.invalidateCacheFor(context: &context,
                                             path: "/Applications/Xcode.app",
                                             logger: mockedLogger)

        XCTAssertEqual(context.resultCache.count, 1)
        XCTAssertEqual(context.operationMap.count, 1)
    }

    func testOperationQueueSelection() throws {
        let mb = 1024 * 1024
        let gb = mb * 1024
        
        // Large applications (size > 10 mb) should always end up in the secondary queue
        var fileInformation = FileInformation(path: "/Applications/XCode.app",
                                              ownerId: 0,
                                              size: 10 * gb)

        var queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.secondary)

        // Small applications (size < 10mb) should always end up in the primary queue
        fileInformation = FileInformation(path: "/bin/bash",
                                          ownerId: 0,
                                          size: 1 * mb)

        queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.primary)

        // Regardless of application size, if the file is not owned by root then it should
        // always end up in the secondary queue
        fileInformation = FileInformation(path: "/bin/bash",
                                          ownerId: 1,
                                          size: 1 * mb)

        queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.secondary)
    }
}
