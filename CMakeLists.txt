cmake_minimum_required(VERSION 3.20)
project(tray_solution LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(find_latest_midl out_var)
    file(GLOB MIDL_CANDIDATES "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/midl.exe")
    if (NOT MIDL_CANDIDATES)
        message(FATAL_ERROR "midl.exe was not found in the Windows 10 SDK.")
    endif()

    list(SORT MIDL_CANDIDATES COMPARE NATURAL ORDER DESCENDING)
    list(GET MIDL_CANDIDATES 0 LATEST_MIDL)
    set(${out_var} "${LATEST_MIDL}" PARENT_SCOPE)
endfunction()

function(apply_static_msvc_runtime target_name)
    set_property(TARGET "${target_name}" PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

find_latest_midl(MIDL_EXECUTABLE)

set(RPC_IDL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpc/tray_service_rpc.idl")
set(RPC_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/rpc")
file(MAKE_DIRECTORY "${RPC_GENERATED_DIR}")

set(RPC_GENERATED_HEADER "${RPC_GENERATED_DIR}/tray_service_rpc.h")
set(RPC_GENERATED_CLIENT "${RPC_GENERATED_DIR}/tray_service_rpc_c.c")
set(RPC_GENERATED_SERVER "${RPC_GENERATED_DIR}/tray_service_rpc_s.c")
add_custom_command(
    OUTPUT
        "${RPC_GENERATED_HEADER}"
        "${RPC_GENERATED_CLIENT}"
        "${RPC_GENERATED_SERVER}"
    COMMAND
        "${MIDL_EXECUTABLE}"
        /nologo
        /env x64
        /app_config
        /char signed
        /target NT100
        /out "${RPC_GENERATED_DIR}"
        "${RPC_IDL_FILE}"
    DEPENDS "${RPC_IDL_FILE}"
    VERBATIM
)

add_library(tray-rpc STATIC
    "${RPC_GENERATED_CLIENT}"
    "${RPC_GENERATED_SERVER}"
    src/common/rpc_memory.cpp
)

target_include_directories(tray-rpc
    PUBLIC
        "${RPC_GENERATED_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
)

target_link_libraries(tray-rpc PUBLIC Rpcrt4)
apply_static_msvc_runtime(tray-rpc)

add_library(tray-common STATIC
    src/common/rpc_client.cpp
    src/common/service_utils.cpp
)

target_include_directories(tray-common
    PUBLIC
        "${RPC_GENERATED_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
)

target_link_libraries(tray-common PUBLIC Advapi32 Rpcrt4 tray-rpc)
apply_static_msvc_runtime(tray-common)

add_executable(tray-app WIN32 src/app/tray_app.cpp)
target_compile_definitions(tray-app PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(tray-app PRIVATE tray-common)
apply_static_msvc_runtime(tray-app)

add_executable(tray-service src/service/service_main.cpp)
target_compile_definitions(tray-service PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(tray-service PRIVATE tray-common tray-rpc Advapi32 Userenv Wtsapi32)
apply_static_msvc_runtime(tray-service)
