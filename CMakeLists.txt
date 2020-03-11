#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.5)
project("sinter" LANGUAGES Swift)

#
# Set the right codesign identity in cmake/options.cmake
#   security find-identity -v -p codesigning
#
# Configure and build:
#   mkdir build && cd build && cmake -G Ninja .. && ninja && sudo ./swift-eevee-sec
#

include("cmake/options.cmake")
include("cmake/codesign.cmake")

function(swiftEeveeSec)
  add_subdirectory("libraries")

  add_executable("${PROJECT_NAME}"
    src/main.swift
    src/EndpointSecurityMessage.swift
    src/EndpointSecurity.swift
    src/AuthorizationManager.swift
    src/CodeSigningUtils.swift
    src/SignatureChecker.swift
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE thirdparty_endpointsecurity)
  codesign("${PROJECT_NAME}")
endfunction()

swiftEeveeSec()

