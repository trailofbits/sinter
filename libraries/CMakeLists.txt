cmake_minimum_required(VERSION 3.16.5)

function(swiftEeveeSecLibraries)
  set(library_list
    EndpointSecurity
  )

  foreach(library ${library_list})
    add_subdirectory("${library}")
  endforeach()
endfunction()

swiftEeveeSecLibraries()

