CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(eventsystem C)

SET(VERSION 0.0.1)
SET(VERSION_MAJOR 0)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

set(CMAKE_SKIP_BUILD_RPATH true)

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

### Required packages
INCLUDE(FindPkgConfig)

pkg_check_modules(libpkgs REQUIRED dlog bundle openssl glib-2.0 capi-base-common)

#FIND_LIBRARY(LIB_DL dl)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

## Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

## build eventsystem library
add_library(eventsystem SHARED
		src/eventsystem.c
		)

#TARGET_LINK_LIBRARIES(eventsystem "-ldl")
TARGET_LINK_LIBRARIES(eventsystem ${libpkgs_LDFLAGS})
SET_TARGET_PROPERTIES(eventsystem PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(eventsystem PROPERTIES VERSION ${VERSION})

# pkgconfig file
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/eventsystem.pc.in ${CMAKE_BINARY_DIR}/eventsystem.pc @ONLY)
configure_file(eventsystem.manifest.in eventsystem.manifest @ONLY)

INSTALL(TARGETS eventsystem DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/eventsystem.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/eventsystem.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/eventsystem_internal.h DESTINATION include)
