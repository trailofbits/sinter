#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.5)

function(swiftEeveeSecLibrariesEndpointSecurity)
  add_library(thirdparty_endpointsecurity INTERFACE)
  target_include_directories(thirdparty_endpointsecurity INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(thirdparty_endpointsecurity INTERFACE "EndpointSecurity")
endfunction()

swiftEeveeSecLibrariesEndpointSecurity()

