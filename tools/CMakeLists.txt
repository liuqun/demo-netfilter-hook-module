cmake_minimum_required(VERSION 3.1)
project(demo LANGUAGES C)
set(demo_SOURCES
  "main.c"
  "get_genl_family_id.c"
  "check_genl_family_id.c"
)
add_executable(userspacetool ${demo_SOURCES})

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBMNL REQUIRED libmnl)
find_library(LIBMNL_LIBRARIES
  NAMES mnl
  HINTS ${LIBMNL_LIBDIR} ${LIBMNL_LIBRARY_DIRS}
)
target_include_directories(userspacetool PRIVATE ${LIBMNL_INCLUSE_DIRS})
target_link_libraries(userspacetool ${LIBMNL_LIBRARIES})
