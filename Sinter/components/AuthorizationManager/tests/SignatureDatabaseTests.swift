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
                                                                    cachedResultOpt: nil,
                                                                    external: false)

        testPath = "/Applications/Google Chrome.app"
        context.operationMap[testPath] = SignatureDatabaseOperation(path: testPath,
                                                                    cachedResultOpt: nil,
                                                                    external: false)

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
        // Application bundles always end up in the secondary queue
        var fileInformation = FileInformation(path: "/Applications/XCode.app",
                                              ownerAccountName: "root",
                                              groupOwnerAccountName: "wheel",
                                              size: 1,
                                              directory: true)

        var queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.secondary)

        // Applications that are not owned by the root user, always end up in the secondary queue
        fileInformation = FileInformation(path: "/usr/local/bin/test_application",
                                          ownerAccountName: "user",
                                          groupOwnerAccountName: "user",
                                          size: 1,
                                          directory: false)

        queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.secondary)

        // Applications that are not owned by the admin/staff/wheel groups, always end up in the secondary queue
        fileInformation = FileInformation(path: "/usr/local/bin/test_application",
                                          ownerAccountName: "root",
                                          groupOwnerAccountName: "user",
                                          size: 1,
                                          directory: false)

        queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        XCTAssertEqual(queueType, OperationQueueType.secondary)

        // Sinter.app always end up in the primary queue, if the owners are correct
        let userList = ["root", "user"]
        let groupList = ["admin", "staff", "wheel", "user"]
        let fileSizeList = [1024, 1048576, 5242880, 10485760, 52428800]
        
        let sinterAppBundlePath = "/Applications/Sinter.app"
        let applicationPathList = ["/Applications/Xcode.app",
                                   sinterAppBundlePath]

        for user in userList {
            for group in groupList {
                for fileSize in fileSizeList {
                    for applicationPath in applicationPathList {
                        fileInformation = FileInformation(path: applicationPath,
                                                          ownerAccountName: user,
                                                          groupOwnerAccountName: group,
                                                          size: fileSize,
                                                          directory: true)

                        let expectedQueueType: OperationQueueType
                        if fileInformation.ownerAccountName == "root" &&
                           fileInformation.groupOwnerAccountName != "user" &&
                           fileInformation.path == sinterAppBundlePath {

                            expectedQueueType = OperationQueueType.primary
                        } else {
                            expectedQueueType = OperationQueueType.secondary
                        }

                        queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
                        XCTAssertEqual(queueType, expectedQueueType)
                    }
                }
            }
        }

        // Applications owned by the root user and one of the approved groups ends up in the primary queue
        // unless they exceed the maximum file size limitation
        for user in userList {
            for group in groupList {
                for fileSize in fileSizeList {
                    fileInformation = FileInformation(path: "/usr/local/bin/test_application",
                                                      ownerAccountName: user,
                                                      groupOwnerAccountName: group,
                                                      size: fileSize,
                                                      directory: false)

                    let expectedQueueType: OperationQueueType
                    if fileInformation.ownerAccountName != "root" ||
                        fileInformation.groupOwnerAccountName == "user" ||
                        fileInformation.size > 10485760 {

                        expectedQueueType = OperationQueueType.secondary
                    } else {
                        expectedQueueType = OperationQueueType.primary
                    }

                    queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
                    XCTAssertEqual(queueType, expectedQueueType)
                }
            }
        }
    }
}
