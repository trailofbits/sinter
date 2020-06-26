//
//  EndpointSecurityClientTests.swift
//  EndpointSecurityClientTests
//
//  Created by Alessandro Gario on 28/05/2020.
//  Copyright © 2020 Trail of Bits. All rights reserved.
//

import XCTest
import EndpointSecurity
import Foundation

@testable import EndpointSecurityClient

class EndpointSecurityClientTests: XCTestCase {
    private func generateContext() -> EndpointSecurityClientContext {
        var context = EndpointSecurityClientContext()
        
        let dummyMessagePtr = UnsafeMutablePointer<es_message_t>.allocate(capacity: 1)

        context.authorizationMessageMap[1] = MessageMapEntry(key: 1,
                                                             timestamp: 1,
                                                             binaryPath: "/Applications/Safari.app",
                                                             unsafeMessagePtr: dummyMessagePtr)

        context.authorizationMessageMap[2] = MessageMapEntry(key: 2,
                                                             timestamp: 2,
                                                             binaryPath: "/Applications/Xcode.app",
                                                             unsafeMessagePtr: dummyMessagePtr)

        context.cachedPathList.insert("/Applications/CMake.app")
        context.cachedPathList.insert("/Applications/iTerm.app")

        return context
    }

    func testFileChangeNotification() throws {
        for notificationType in EndpointSecurityFileChangeNotificationType.allCases {
            var context = generateContext()
            var resetCache = false
            var invalidatedRequestList = [MessageMapEntry]()

            var message = EndpointSecurityFileChangeNotification(type: notificationType,
                                                                 pathList: ["/Applications/Google Chrome.app"])
            
            EndpointSecurityClient.processFileChangeNotification(context: &context,
                                                                 resetCache: &resetCache,
                                                                 invalidatedRequestList: &invalidatedRequestList,
                                                                 message: message)
            
            XCTAssertFalse(resetCache)
            XCTAssertTrue(invalidatedRequestList.isEmpty)
            XCTAssertEqual(context.authorizationMessageMap.count, 2)
            XCTAssertEqual(context.cachedPathList.count, 2)

            message = EndpointSecurityFileChangeNotification(type: notificationType,
                                                             pathList: ["/Applications/CMake.app"])
            
            EndpointSecurityClient.processFileChangeNotification(context: &context,
                                                                 resetCache: &resetCache,
                                                                 invalidatedRequestList: &invalidatedRequestList,
                                                                 message: message)
            
            XCTAssertTrue(resetCache)
            XCTAssertTrue(invalidatedRequestList.isEmpty)
            XCTAssertEqual(context.authorizationMessageMap.count, 2)
            XCTAssertEqual(context.cachedPathList.count, 2)

            message = EndpointSecurityFileChangeNotification(type: notificationType,
                                                             pathList: ["/Applications/Xcode.app"])
            
            EndpointSecurityClient.processFileChangeNotification(context: &context,
                                                                 resetCache: &resetCache,
                                                                 invalidatedRequestList: &invalidatedRequestList,
                                                                 message: message)
            
            XCTAssertFalse(resetCache)
            XCTAssertEqual(invalidatedRequestList.count, 1)
            XCTAssertEqual(context.authorizationMessageMap.count, 1)
            XCTAssertEqual(context.cachedPathList.count, 2)
        }
    }
    
    func testEventExpiration() throws {
        let context = generateContext()
        var expiredMessageList = [MessageMapEntry]()

        EndpointSecurityClient.expireEvents(context: context,
                                            expiredMessageList: &expiredMessageList,
                                            currentTimestamp: 0,
                                            maxRequestAge: 1)
        
        XCTAssertTrue(expiredMessageList.isEmpty)
        XCTAssertEqual(context.authorizationMessageMap.count, 2)

        EndpointSecurityClient.expireEvents(context: context,
                                            expiredMessageList: &expiredMessageList,
                                            currentTimestamp: 2,
                                            maxRequestAge: 1)
        
        XCTAssertEqual(expiredMessageList.count, 1)
        XCTAssertEqual(context.authorizationMessageMap.count, 2)

        EndpointSecurityClient.expireEvents(context: context,
                                            expiredMessageList: &expiredMessageList,
                                            currentTimestamp: 3,
                                            maxRequestAge: 1)
        
        XCTAssertEqual(expiredMessageList.count, 2)
        XCTAssertEqual(context.authorizationMessageMap.count, 2)
    }
    
    func testEventExpirationHandler() throws {
        var context = generateContext()
        let mockedApi = createMockedEndpointSecurityAPI()
        let mockedLogger = createMockedLogger()

        var clientOpt: OpaquePointer?
        _ = mockedApi.newClient(client: &clientOpt) { _,_ in }
        
        var expiredEventcount = 0
        
        EndpointSecurityClient.onEventExpiration(context: &context,
                                                 api: mockedApi,
                                                 logger: mockedLogger,
                                                 client: clientOpt!) { _ in expiredEventcount += 1 }

        XCTAssertTrue(context.authorizationMessageMap.isEmpty)
        XCTAssertEqual(expiredEventcount, 2)
    }
    
    func testCacheInvalidationAPI() throws {
        var context = generateContext()
        let mockedApi = createMockedEndpointSecurityAPI()
        let mockedLogger = createMockedLogger()

        var clientOpt: OpaquePointer?
        _ = mockedApi.newClient(client: &clientOpt) { _,_ in }
        
        let succeeded = EndpointSecurityClient.invalidateCache(context: &context,
                                                               api: mockedApi,
                                                               client: clientOpt!,
                                                               logger: mockedLogger)

        XCTAssertTrue(succeeded)
        XCTAssertTrue(context.cachedPathList.isEmpty)
    }
    
    func testSetAuthorizationAPI() throws {
        var context = generateContext()
        let mockedApi = createMockedEndpointSecurityAPI()
        let mockedLogger = createMockedLogger()

        var clientOpt: OpaquePointer?
        _ = mockedApi.newClient(client: &clientOpt) { _,_ in }
        
        var succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                                api: mockedApi,
                                                                logger: mockedLogger,
                                                                client: clientOpt!,
                                                                identifier: 9999,
                                                                allow: true,
                                                                cache: false)

        XCTAssertFalse(succeeded)
        XCTAssertEqual(context.cachedPathList.count, 2)

        succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                            api: mockedApi,
                                                            logger: mockedLogger,
                                                            client: clientOpt!,
                                                            identifier: 1,
                                                            allow: true,
                                                            cache: false)

        XCTAssertTrue(succeeded)
        XCTAssertEqual(context.cachedPathList.count, 2)

        succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                            api: mockedApi,
                                                            logger: mockedLogger,
                                                            client: clientOpt!,
                                                            identifier: 1,
                                                            allow: true,
                                                            cache: false)

        XCTAssertFalse(succeeded)
        XCTAssertEqual(context.cachedPathList.count, 2)

        succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                            api: mockedApi,
                                                            logger: mockedLogger,
                                                            client: clientOpt!,
                                                            identifier: 2,
                                                            allow: true,
                                                            cache: true)

        XCTAssertTrue(succeeded)
        XCTAssertEqual(context.cachedPathList.count, 3)

        succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                            api: mockedApi,
                                                            logger: mockedLogger,
                                                            client: clientOpt!,
                                                            identifier: 2,
                                                            allow: true,
                                                            cache: true)

        XCTAssertFalse(succeeded)
        XCTAssertEqual(context.cachedPathList.count, 3)
    }
}
