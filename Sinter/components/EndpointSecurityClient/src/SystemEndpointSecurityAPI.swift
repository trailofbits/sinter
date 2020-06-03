/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import EndpointSecurity

fileprivate final class SystemEndpointSecurityAPI : EndpointSecurityAPIInterface {
    func newClient(client: inout OpaquePointer?,
                   handler: @escaping es_handler_block_t) -> es_new_client_result_t {

        return es_new_client(&client, handler)
    }

    func deleteClient(client: OpaquePointer) -> es_return_t {
        return es_delete_client(client)
    }
    
    func subscribe(client: OpaquePointer,
                   events: UnsafePointer<es_event_type_t>,
                   eventCount: UInt32) -> es_return_t {

        return es_subscribe(client,
                            events,
                            eventCount)
    }

    func unsubscribeAll(client: OpaquePointer) -> es_return_t {
        return es_unsubscribe_all(client)
    }

    func respondAuthResult(client: OpaquePointer,
                           message: UnsafePointer<es_message_t>,
                           result: es_auth_result_t,
                           cache: Bool) -> es_respond_result_t {

        return es_respond_auth_result(client,
                                      message,
                                      result,
                                      cache)
    }

    func copyMessage(msg: UnsafePointer<es_message_t>) -> UnsafeMutablePointer<es_message_t>? {
        return es_copy_message(msg)
    }

    func freeMessage(msg: UnsafeMutablePointer<es_message_t>) {
        es_free_message(msg)
    }
    
    func clearCache(client: OpaquePointer) -> es_clear_cache_result_t {
        return es_clear_cache(client)
    }
}

func createSystemEndpointSecurityAPI() -> EndpointSecurityAPIInterface {
    return SystemEndpointSecurityAPI()
}
