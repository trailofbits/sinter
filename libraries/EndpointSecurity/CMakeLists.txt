cmake_minimum_required(VERSION 3.16.5)

function(swiftEeveeSecLibrariesEndpointSecurity)
  add_library(thirdparty_endpointsecurity INTERFACE)
  target_include_directories(thirdparty_endpointsecurity INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(thirdparty_endpointsecurity INTERFACE "EndpointSecurity")
endfunction()

swiftEeveeSecLibrariesEndpointSecurity()

