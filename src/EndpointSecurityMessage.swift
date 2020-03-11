/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import EndpointSecurity

struct EndpointSecurityMessage {
  var unsafe_msg_ptr: UnsafeMutablePointer<es_message_t>;
  var binary_path: String;
  var signature_status: CodeSignatureStatus?;
}

