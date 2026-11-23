cmake_minimum_required(VERSION 3.13)

project(DATUM VERSION 0.5.1 LANGUAGES C)

# Enable C23 if supported, else fall back to C11 for compatibility
if(CMAKE_VERSION VERSION_LESS "3.21")
    # Older CMake: C23 not recognized; use C11
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
else()
    # CMake 3.21+: C23 is available
    set(CMAKE_C_STANDARD 23)
    set(CMAKE_C_STANDARD_REQUIRED OFF)
endif()

option(ENABLE_API "Build API support." ON)
set(DATUM_SV2_BACKEND "sri" CACHE STRING "Stratum V2 protocol layer: sri (SRI's crates through external/sri-c-ffi, needs cargo) or c (the C core in src/sv2, needs libsecp256k1 >= 0.4)")
set_property(CACHE DATUM_SV2_BACKEND PROPERTY STRINGS sri c)

include(GNUInstallDirs)

add_executable(datum_gateway
	src/datum_blocktemplates.c
	src/datum_coinbaser.c
	src/datum_conf.c
	src/datum_conf_tests.c
	src/datum_gateway.c
	src/datum_jsonrpc.c
	src/datum_logger.c
	src/datum_protocol.c
	src/datum_queue.c
	src/datum_sockets.c
	src/datum_stratum.c
	src/datum_stratum_dupes.c
	src/datum_stratum_tests.c
	src/datum_stratum_dupes_tests.c
	src/datum_submitblock.c
	src/datum_sv2.c
	src/datum_sv2_tests.c
	src/datum_utils.c
	src/datum_utils_tests.c
	src/thirdparty_base58.c
	src/thirdparty_segwit_addr.c
	${CMAKE_CURRENT_BINARY_DIR}/web_resources.h
)
install(TARGETS datum_gateway DESTINATION bin)

set(WEB_RESOURCES
	www/auth_failed.html
	www/home.html
	www/clients_top.html
	www/coinbaser_top.html
	www/config.html
	www/config_errors.html
	www/config_noauth_top.html
	www/config_restart.html
	www/threads_top.html
	www/foot.html
	www/assets/post.js
	www/assets/style.css
	www/assets/icons/datum_logo.svg
	www/assets/icons/favicon.ico
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)
if(ENABLE_API)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
endif()
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(Threads REQUIRED)

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CMakePushCheckState)
cmake_push_check_state(RESET)
string(APPEND CMAKE_REQUIRED_FLAGS -Wno-error)

set(POW_LIBS "")
check_library_exists(m pow "" LIBM)
if(LIBM)
	list(APPEND POW_LIBS "m")
endif()

set(ARGP_LIBS "")
check_function_exists(argp_parse HAVE_ARGP_PARSE)
if(NOT HAVE_ARGP_PARSE)
	check_library_exists(argp argp_parse "" ARGP)
	if(NOT ARGP AND CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		# Workaround bug where CMake doesn't check the standard install location on FreeBSD
		unset(ARGP CACHE)
		check_library_exists(argp argp_parse "/usr/local/lib" ARGP)
	endif()
	if(ARGP)
		list(APPEND ARGP_LIBS "argp")
	endif()
endif()

check_function_exists(epoll_wait HAVE_EPOLL_WAIT)
if(HAVE_EPOLL_WAIT)
	set(EPOLL_SHIM_INCLUDE_DIRS "")
	set(EPOLL_SHIM_LIBRARIES "")
else()
	pkg_check_modules(EPOLL_SHIM REQUIRED epoll-shim)
endif()

cmake_pop_check_state()

add_custom_target(generate_git_version
	BYPRODUCTS ${PROJECT_BINARY_DIR}/git_version.h
	COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/git_version.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
	DEPENDS cmake/script/GenerateBuildInfo.cmake
	COMMENT "Generating git_version.h"
	VERBATIM
)
add_dependencies(datum_gateway generate_git_version)

add_custom_command(
	OUTPUT web_resources.h
	COMMAND ${CMAKE_COMMAND} "-DINPUT_FILES=${WEB_RESOURCES}" -DOUTPUT_FILE=web_resources.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/EmbedResources.cmake
	DEPENDS ${WEB_RESOURCES} cmake/script/EmbedResources.cmake
	VERBATIM
)

target_include_directories(datum_gateway
	PRIVATE
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
	${EPOLL_SHIM_INCLUDE_DIRS}
	${CURL_INCLUDE_DIRS}
	${JANSSON_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS}
)
target_link_directories(datum_gateway
	PUBLIC
	${CURL_LIBRARY_DIRS}
	${JANSSON_LIBRARY_DIRS}
	${SODIUM_LIBRARY_DIRS}
)
target_link_libraries(datum_gateway
	PUBLIC
	${POW_LIBS}
	Threads::Threads
	${ARGP_LIBS}
	${EPOLL_SHIM_LIBRARIES}
	${CURL_LIBRARIES} ${CURL_LDFLAGS} ${CURL_LDFLAGS_OTHER}
	${JANSSON_LIBRARIES} ${JANSSON_LDFLAGS} ${JANSSON_LDFLAGS_OTHER}
	${SODIUM_LIBRARIES} ${SODIUM_LDFLAGS} ${SODIUM_LDFLAGS_OTHER}
)
target_compile_options(datum_gateway
	PUBLIC
	${CURL_CFLAGS} ${CURL_CFLAGS_OTHER}
	${JANSSON_CFLAGS} ${JANSSON_CFLAGS_OTHER}
	${SODIUM_CFLAGS} ${SODIUM_CFLAGS_OTHER}
)

# Stratum V2: src/datum_sv2.c runs on one of two protocol layers, picked
# with -DDATUM_SV2_BACKEND (see doc/STRATUM_V2.md).
#   sri  SRI's Rust crates behind the C API in external/sri-c-ffi, which
#        cargo builds here, or an installed libsv2_sri that pkg-config
#        finds as sv2_sri.
#   c    the C core in src/sv2, on libsodium and libsecp256k1 >= 0.4
#        (ElligatorSwift arrived in 0.4.0).
if(DATUM_SV2_BACKEND STREQUAL "c")
	pkg_check_modules(SECP256K1 REQUIRED libsecp256k1>=0.4.0)
	target_sources(datum_gateway PRIVATE
		src/sv2/datum_sv2_channel.c
		src/sv2/sv2_codec.c
		src/sv2/sv2_crypto_sodium.c
		src/sv2/sv2_frame.c
		src/sv2/sv2_msg_common.c
		src/sv2/sv2_msg_mining.c
		src/sv2/sv2_noise.c
	)
	# the channel layer in src/sv2 includes the gateway's headers from src
	target_include_directories(datum_gateway PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/sv2 ${CMAKE_CURRENT_SOURCE_DIR}/src ${SECP256K1_INCLUDE_DIRS})
	target_link_directories(datum_gateway PUBLIC ${SECP256K1_LIBRARY_DIRS})
	target_link_libraries(datum_gateway PUBLIC ${SECP256K1_LIBRARIES} ${SECP256K1_LDFLAGS} ${SECP256K1_LDFLAGS_OTHER})
	target_compile_options(datum_gateway PUBLIC ${SECP256K1_CFLAGS} ${SECP256K1_CFLAGS_OTHER})
	set(SV2_PREVIEW
		"Stratum V2 layer: c, the C core in src/sv2 (no Rust)"
		"  libsecp256k1:   ${SECP256K1_VERSION}"
		"  libsodium:      ${SODIUM_VERSION}"
		"  Switch to SRI's Rust crates with -DDATUM_SV2_BACKEND=sri (needs cargo, Rust 1.85 or newer)"
	)
elseif(DATUM_SV2_BACKEND STREQUAL "sri")
	target_sources(datum_gateway PRIVATE
		src/sv2_sri/datum_sv2_channel_sri.c
		src/sv2_sri/sv2_backend_sri.c
	)
	# src/sv2_sri goes first: its sv2_noise.h and secp256k1.h stand in for
	# the C core's and libsecp256k1's; the message headers come from src/sv2
	# and the gateway's from src
	target_include_directories(datum_gateway PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src/sv2_sri
		${CMAKE_CURRENT_SOURCE_DIR}/src/sv2
		${CMAKE_CURRENT_SOURCE_DIR}/src
	)
	pkg_check_modules(SV2_SRI QUIET sv2_sri)
	if(SV2_SRI_FOUND)
		message(STATUS "Stratum V2 protocol layer: libsv2_sri ${SV2_SRI_VERSION} from pkg-config")
		target_include_directories(datum_gateway PRIVATE ${SV2_SRI_INCLUDE_DIRS})
		target_link_directories(datum_gateway PUBLIC ${SV2_SRI_LIBRARY_DIRS})
		target_link_libraries(datum_gateway PUBLIC ${SV2_SRI_LIBRARIES} ${SV2_SRI_LDFLAGS} ${SV2_SRI_LDFLAGS_OTHER})
		target_compile_options(datum_gateway PUBLIC ${SV2_SRI_CFLAGS} ${SV2_SRI_CFLAGS_OTHER})
		set(SV2_PREVIEW
			"Stratum V2 layer: sri, SRI's Rust crates through an installed libsv2_sri"
			"  libsv2_sri:     ${SV2_SRI_VERSION}, found by pkg-config (no Rust is built here)"
		)
	else()
		find_program(CARGO cargo HINTS $ENV{CARGO_HOME}/bin $ENV{HOME}/.cargo/bin)
		get_filename_component(CARGO_BIN_DIR "${CARGO}" DIRECTORY)
		find_program(RUSTC rustc HINTS ${CARGO_BIN_DIR})
		if(NOT CARGO OR NOT RUSTC)
			message(FATAL_ERROR
				"The sri Stratum V2 protocol layer builds external/sri-c-ffi with cargo "
				"(Rust 1.85 or newer), or links an installed libsv2_sri found by pkg-config "
				"as sv2_sri. Install Rust, or configure with -DDATUM_SV2_BACKEND=c to build "
				"the C core instead.")
		endif()
		message(STATUS "Stratum V2 protocol layer: external/sri-c-ffi, built with ${CARGO}")
		set(SV2_SRI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/sri-c-ffi)
		set(SV2_SRI_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/sri-c-ffi)
		set(SV2_SRI_LIB ${SV2_SRI_TARGET_DIR}/release/${CMAKE_STATIC_LIBRARY_PREFIX}sv2_sri${CMAKE_STATIC_LIBRARY_SUFFIX})
		# A static library does not record the system libraries it needs;
		# rustc prints them for an empty crate, which needs the same ones.
		file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sv2_sri_native_libs.rs "")
		execute_process(
			COMMAND ${RUSTC} --crate-type staticlib --crate-name sv2_sri_native_libs --print native-static-libs
				-o ${CMAKE_CURRENT_BINARY_DIR}/libsv2_sri_native_libs.a ${CMAKE_CURRENT_BINARY_DIR}/sv2_sri_native_libs.rs
			RESULT_VARIABLE RUSTC_RESULT
			ERROR_VARIABLE RUSTC_OUTPUT
		)
		if(NOT RUSTC_RESULT EQUAL 0 OR NOT RUSTC_OUTPUT MATCHES "native-static-libs: ([^\r\n]*)")
			message(FATAL_ERROR "rustc did not report the system libraries a Rust static library needs:\n${RUSTC_OUTPUT}")
		endif()
		separate_arguments(SV2_SRI_NATIVE_LIBS UNIX_COMMAND "${CMAKE_MATCH_1}")
		list(REMOVE_DUPLICATES SV2_SRI_NATIVE_LIBS)
		file(GLOB_RECURSE SV2_SRI_SOURCES CONFIGURE_DEPENDS ${SV2_SRI_DIR}/src/*.rs)
		add_custom_command(
			OUTPUT ${SV2_SRI_LIB}
			# cargo runs its own jobs: make's jobserver is not passed to a
			# USES_TERMINAL command
			COMMAND ${CMAKE_COMMAND} -E env --unset=MAKEFLAGS --unset=MFLAGS CARGO_TARGET_DIR=${SV2_SRI_TARGET_DIR}
				${CARGO} build --release --locked --lib --manifest-path ${SV2_SRI_DIR}/Cargo.toml
			DEPENDS ${SV2_SRI_SOURCES} ${SV2_SRI_DIR}/Cargo.toml ${SV2_SRI_DIR}/Cargo.lock
			COMMENT "Building the Stratum V2 protocol layer in external/sri-c-ffi with cargo"
			USES_TERMINAL
			VERBATIM
		)
		add_custom_target(sv2_sri_lib DEPENDS ${SV2_SRI_LIB})
		add_dependencies(datum_gateway sv2_sri_lib)
		target_include_directories(datum_gateway PRIVATE ${SV2_SRI_DIR}/include)
		target_link_libraries(datum_gateway PUBLIC ${SV2_SRI_LIB} ${SV2_SRI_NATIVE_LIBS})
		execute_process(COMMAND ${CARGO} --version OUTPUT_VARIABLE CARGO_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
		execute_process(COMMAND ${RUSTC} --version OUTPUT_VARIABLE RUSTC_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
		string(REPLACE ";" " " SV2_SRI_NATIVE_LIBS_TEXT "${SV2_SRI_NATIVE_LIBS}")
		if(DEFINED ENV{RUSTFLAGS})
			set(SV2_RUSTFLAGS "$ENV{RUSTFLAGS}")
		else()
			set(SV2_RUSTFLAGS "(not set)")
		endif()
		set(SV2_PREVIEW
			"Stratum V2 layer: sri, SRI's Rust crates through external/sri-c-ffi, built here with cargo"
			"  cargo:          ${CARGO_VERSION} (${CARGO})"
			"  rustc:          ${RUSTC_VERSION}"
			"  Rust build:     cargo build --release --locked (profile.release in external/sri-c-ffi/Cargo.toml)"
			"  RUSTFLAGS:      ${SV2_RUSTFLAGS} at configure time (cargo reads it from the build's environment)"
			"  System libs:    ${SV2_SRI_NATIVE_LIBS_TEXT}"
			"  Switch to the C core with -DDATUM_SV2_BACKEND=c (no Rust, needs libsecp256k1 0.4 or newer)"
		)
	endif()
else()
	message(FATAL_ERROR "DATUM_SV2_BACKEND must be sri or c, not '${DATUM_SV2_BACKEND}'")
endif()

# `make preview` (or `cmake --build <dir> --target preview`) prints what
# this configuration builds: the Stratum V2 protocol layer, Rust or C, with
# its toolchain, and the C compiler and flags.  It builds nothing.
string(TOUPPER "${CMAKE_BUILD_TYPE}" PREVIEW_BUILD_TYPE)
if(PREVIEW_BUILD_TYPE)
	set(PREVIEW_BUILD "${CMAKE_BUILD_TYPE}")
else()
	set(PREVIEW_BUILD "(none set)")
endif()
if(DEFINED CMAKE_C_EXTENSIONS AND NOT CMAKE_C_EXTENSIONS)
	set(PREVIEW_STD "c${CMAKE_C_STANDARD}")
else()
	set(PREVIEW_STD "gnu${CMAKE_C_STANDARD}")
endif()
if(NOT CMAKE_C_STANDARD_REQUIRED)
	string(APPEND PREVIEW_STD ", or an older standard if the compiler lacks it")
endif()
string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${PREVIEW_BUILD_TYPE}}" PREVIEW_C_FLAGS)
if(NOT PREVIEW_C_FLAGS)
	set(PREVIEW_C_FLAGS "(none)")
endif()
set(PREVIEW_LINES
	"DATUM Gateway ${PROJECT_VERSION} build preview (nothing is built)"
	"C compiler:       ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} (${CMAKE_C_COMPILER})"
	"C standard:       ${PREVIEW_STD}"
	"Build type:       ${PREVIEW_BUILD}"
	"C flags:          ${PREVIEW_C_FLAGS}"
	"JSON API:         ${ENABLE_API}"
	${SV2_PREVIEW}
)
set(PREVIEW_COMMANDS)
foreach(line IN LISTS PREVIEW_LINES)
	list(APPEND PREVIEW_COMMANDS COMMAND ${CMAKE_COMMAND} -E echo "${line}")
endforeach()
add_custom_target(preview ${PREVIEW_COMMANDS} VERBATIM)

if(ENABLE_API)
	target_sources(datum_gateway PRIVATE src/datum_api.c src/datum_json_api.c)
	target_include_directories(datum_gateway PRIVATE ${MICROHTTPD_INCLUDE_DIRS})
	target_link_directories(datum_gateway PUBLIC ${MICROHTTPD_LIBRARY_DIRS})
	target_link_libraries(datum_gateway PUBLIC ${MICROHTTPD_LIBRARIES} ${MICROHTTPD_LDFLAGS} ${MICROHTTPD_LDFLAGS_OTHER})
	target_compile_options(datum_gateway PUBLIC
		-DENABLE_API
		${MICROHTTPD_CFLAGS} ${MICROHTTPD_CFLAGS_OTHER}
	)
endif()

install(FILES README.md CONTRIBUTING.md SECURITY.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES doc/DATUM_recommended_setup-network_diagram.svg DESTINATION ${CMAKE_INSTALL_DOCDIR}/doc)
install(FILES doc/INSTALL.md doc/OPTIMIZATIONS.md doc/STRATUM_V2.md doc/usernames.md doc/json_api.md doc/original.md doc/original.txt DESTINATION ${CMAKE_INSTALL_DOCDIR}/doc)

set(PREGEN_DOC ${CMAKE_SOURCE_DIR}/doc/example_datum_gateway_config.json)
install(FILES ${PREGEN_DOC} DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES ${PREGEN_DOC} DESTINATION ${CMAKE_INSTALL_DOCDIR}/doc)

if(NOT CMAKE_CROSSCOMPILING)
	set(GENERATED_DOC ${CMAKE_BINARY_DIR}/CMakeFiles/generated_example_datum_gateway_config.json)
	
	add_custom_command(
		TARGET datum_gateway
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -DDATUM_GATEWAY=$<TARGET_FILE:datum_gateway> -DGENERATED_DOC=${GENERATED_DOC} -DPREGEN_DOC=${PREGEN_DOC} -P ${PROJECT_SOURCE_DIR}/cmake/script/VerifyExample.cmake
		COMMENT "Verifying pre-generated documentation is up-to-date"
		VERBATIM
	)
endif()
