/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import EndpointSecurity

@testable import EndpointSecurityClient

fileprivate final class MockedEndpointSecurityAPI : EndpointSecurityAPIInterface {
    func newClient(client: inout OpaquePointer?,
                   handler: @escaping es_handler_block_t) -> es_new_client_result_t {

        let dummy = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        client = OpaquePointer(dummy)

        return ES_NEW_CLIENT_RESULT_SUCCESS
    }

    func deleteClient(client: OpaquePointer) -> es_return_t {
        return ES_RETURN_SUCCESS
    }
    
    func subscribe(client: OpaquePointer,
                   events: UnsafePointer<es_event_type_t>,
                   eventCount: UInt32) -> es_return_t {

        return ES_RETURN_SUCCESS
    }

    func unsubscribeAll(client: OpaquePointer) -> es_return_t {
        return ES_RETURN_SUCCESS
    }

    func respondAuthResult(client: OpaquePointer,
                           message: UnsafePointer<es_message_t>,
                           result: es_auth_result_t,
                           cache: Bool) -> es_respond_result_t {

        return ES_RESPOND_RESULT_SUCCESS
    }

    func copyMessage(msg: UnsafePointer<es_message_t>) -> UnsafeMutablePointer<es_message_t>? {
        return UnsafeMutablePointer<es_message_t>(mutating: msg)
    }

    func freeMessage(msg: UnsafeMutablePointer<es_message_t>) { }

    func clearCache(client: OpaquePointer) -> es_clear_cache_result_t {
        return ES_CLEAR_CACHE_RESULT_SUCCESS
    }
}

func createMockedEndpointSecurityAPI() -> EndpointSecurityAPIInterface {
    return MockedEndpointSecurityAPI()
}
