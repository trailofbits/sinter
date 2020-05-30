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

    /*func testOperationQueueSelection() throws {
        var context = generateContext()

        XCTAssertEqual(context.resultCache.count, 3)
        XCTAssertEqual(context.operationMap.count, 2)

        var message = EndpointSecurityExecAuthorization(binaryPath: "/Applications/Xcode.app",
                                                        parentProcessId: 0,
                                                        processId: 0,
                                                        userId: 0,
                                                        groupId: 0,
                                                        codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                                      hash: "91BFCC1CE8BCE7473D35FD00BDDF33AF52A1D2FD"),
                                                        signingIdentifier: "com.apple.Safari",
                                                        teamIdentifier: "",
                                                        platformBinary: true)

        SignatureDatabase.checkSignatureFor(context: &context,
                                            message: message,
                                            fileInformationOpt: FileInformation(path: message.binaryPath,
                                                                                ownerId: 0,
                                                                                size: 10737418240)) { _,_  in }

        message = EndpointSecurityExecAuthorization(binaryPath: "/bin/zsh",
                                                    parentProcessId: 0,
                                                    processId: 0,
                                                    userId: 0,
                                                    groupId: 0,
                                                    codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                                  hash: "549629A736F078FC304EE55CBA2D525F4D43488B"),
                                                    signingIdentifier: "com.apple.zsh",
                                                    teamIdentifier: "",
                                                    platformBinary: true)

        SignatureDatabase.checkSignatureFor(context: &context,
                                            message: message,
                                            fileInformationOpt: FileInformation(path: message.binaryPath,
                                                                                ownerId: 0,
                                                                                size: 637840)) { _,_  in }

        message = EndpointSecurityExecAuthorization(binaryPath: "/bin/bash",
                                                    parentProcessId: 0,
                                                    processId: 0,
                                                    userId: 0,
                                                    groupId: 0,
                                                    codeDirectoryHash: BinaryHash(type: BinaryHashType.truncatedSha256,
                                                                                  hash: "D322B5B0D920367DCE6A10576F96A1B0F7CFDB59"),
                                                    signingIdentifier: "com.apple.bash",
                                                    teamIdentifier: "",
                                                    platformBinary: true)

        SignatureDatabase.checkSignatureFor(context: &context,
                                            message: message,
                                            fileInformationOpt: FileInformation(path: message.binaryPath,
                                                                                ownerId: 1,
                                                                                size: 637840)) { _,_  in }
        
        
        XCTAssertEqual(context.primaryOperationQueue.operationCount, 1)
        XCTAssertEqual(context.secondaryOperationQueue.operationCount, 2)
    }*/
}
