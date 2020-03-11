/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import Dispatch

func main() {
  if let auth_manager = AuthorizationManager() {
    auth_manager.exec()

  } else {
    print("Failed to initialize the EndpointSecurityClient object");
  }
}

main()
