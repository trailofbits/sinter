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

  add_custom_command(
    TARGET "${PROJECT_NAME}" POST_BUILD
    COMMAND codesign --entitlements "${CMAKE_CURRENT_SOURCE_DIR}/plist/entitlements.plist" --force -s "${SINTER_CODESIGN_IDENTITY}" -v "$<TARGET_FILE:${PROJECT_NAME}>"
    COMMENT "Codesigning target ${PROJECT_NAME}..."
    VERBATIM
  )
endfunction()

swiftEeveeSec()

