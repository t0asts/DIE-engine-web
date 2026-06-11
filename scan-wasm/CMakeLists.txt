
cmake_minimum_required(VERSION 3.21)
project(scan_engine LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR
        "scan-wasm/CMakeLists.txt is for Emscripten builds only. "
        "Run via scan-wasm/build.sh inside the dev container.")
endif()

set(DIE_ROOT      ${CMAKE_CURRENT_SOURCE_DIR}/third_party/DIE-engine)
set(SCAN_WASM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(NOT EXISTS ${DIE_ROOT}/XScanEngine/xscanengine.cmake)
    message(FATAL_ERROR
        "DIE-engine submodule missing or empty at ${DIE_ROOT}. "
        "Run: git submodule update --init --recursive in the parent repo.")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core)
qt_standard_project_setup()

add_subdirectory(${DIE_ROOT}/XArchive/3rdparty/bzip2 ${CMAKE_BINARY_DIR}/_bzip2)
add_subdirectory(${DIE_ROOT}/XArchive/3rdparty/lzma  ${CMAKE_BINARY_DIR}/_lzma)
add_subdirectory(${DIE_ROOT}/XArchive/3rdparty/ppmd  ${CMAKE_BINARY_DIR}/_ppmd)

set(_CS_SRC ${DIE_ROOT}/XCapstone/3rdparty/Capstone/src)
add_library(capstone STATIC
    ${_CS_SRC}/MCInst.c
    ${_CS_SRC}/MCInstrDesc.c
    ${_CS_SRC}/MCRegisterInfo.c
    ${_CS_SRC}/SStream.c
    ${_CS_SRC}/cs.c
    ${_CS_SRC}/utils.c
    ${_CS_SRC}/arch/X86/X86Disassembler.c
    ${_CS_SRC}/arch/X86/X86DisassemblerDecoder.c
    ${_CS_SRC}/arch/X86/X86IntelInstPrinter.c
    ${_CS_SRC}/arch/X86/X86InstPrinterCommon.c
    ${_CS_SRC}/arch/X86/X86Mapping.c
    ${_CS_SRC}/arch/X86/X86Module.c
    ${_CS_SRC}/arch/ARM/ARMDisassembler.c
    ${_CS_SRC}/arch/ARM/ARMInstPrinter.c
    ${_CS_SRC}/arch/ARM/ARMMapping.c
    ${_CS_SRC}/arch/ARM/ARMModule.c
    ${_CS_SRC}/arch/AArch64/AArch64BaseInfo.c
    ${_CS_SRC}/arch/AArch64/AArch64Disassembler.c
    ${_CS_SRC}/arch/AArch64/AArch64InstPrinter.c
    ${_CS_SRC}/arch/AArch64/AArch64Mapping.c
    ${_CS_SRC}/arch/AArch64/AArch64Module.c
    ${_CS_SRC}/arch/Mips/MipsDisassembler.c
    ${_CS_SRC}/arch/Mips/MipsInstPrinter.c
    ${_CS_SRC}/arch/Mips/MipsMapping.c
    ${_CS_SRC}/arch/Mips/MipsModule.c
    ${_CS_SRC}/arch/PowerPC/PPCDisassembler.c
    ${_CS_SRC}/arch/PowerPC/PPCInstPrinter.c
    ${_CS_SRC}/arch/PowerPC/PPCMapping.c
    ${_CS_SRC}/arch/PowerPC/PPCModule.c
    ${_CS_SRC}/arch/RISCV/RISCVDisassembler.c
    ${_CS_SRC}/arch/RISCV/RISCVInstPrinter.c
    ${_CS_SRC}/arch/RISCV/RISCVMapping.c
    ${_CS_SRC}/arch/RISCV/RISCVModule.c
)
target_include_directories(capstone PUBLIC ${_CS_SRC}/include)
target_compile_definitions(capstone PRIVATE
    CAPSTONE_HAS_X86 CAPSTONE_HAS_ARM CAPSTONE_HAS_ARM64
    CAPSTONE_HAS_MIPS CAPSTONE_HAS_POWERPC CAPSTONE_HAS_RISCV
    CAPSTONE_X86_ATT_DISABLE
    CAPSTONE_DIET_NO CAPSTONE_USE_SYS_DYN_MEM _LIB
)
target_compile_options(capstone PRIVATE
    -Os -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-variable)
set_target_properties(capstone PROPERTIES LINKER_LANGUAGE C POSITION_INDEPENDENT_CODE ON)

include(${DIE_ROOT}/XCapstone/xcapstone.cmake)

add_subdirectory(${DIE_ROOT}/XCppfilt ${CMAKE_BINARY_DIR}/_cppfilt)

add_subdirectory(${DIE_ROOT}/XYara/3rdparty/yara ${CMAKE_BINARY_DIR}/_yara)
target_compile_definitions(yara PRIVATE
    BUCKETS_128 CHECKSUM_1B HAVE_MEMMEM HAVE_STDBOOL_H HAVE_TIMEGM HAVE_CLOCK_GETTIME)
target_compile_options(yara PRIVATE -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-variable)

include(${DIE_ROOT}/Formats/xformats.cmake)
include(${DIE_ROOT}/SpecAbstract/specabstract.cmake)
include(${DIE_ROOT}/XStaticUnpacker/xstaticunpacker.cmake)
include(${DIE_ROOT}/XScanEngine/xscanengine.cmake)
include(${DIE_ROOT}/XFileInfo/xfileinfo.cmake)
include(${DIE_ROOT}/XCppfilt/xcppfilt.cmake)
include(${DIE_ROOT}/XMIME/xmime.cmake)
include(${DIE_ROOT}/XDisasmCore/xdisasmcore.cmake)
include(${DIE_ROOT}/XArchive/xarchive.cmake)

set(_die_excluded_decoders
    "Algos/xdeflatedecoder\\.(cpp|h)$"
    "Algos/zstddeclib\\.(cpp|h)$"
    "Algos/brotlideclib\\.(cpp|h)$"
    "Algos/xzstddecoder\\.(cpp|h)$"
    "Algos/xbrotlidecoder\\.(cpp|h)$"
)
foreach(_var XARCHIVE_SOURCES XFORMATS_SOURCES XSCANENGINE_SOURCES
            SPECABSTRACT_SOURCES XSTATICUNPACKER_SOURCES XFILEINFO_SOURCES
            XCPPFILT_SOURCES XMIME_SOURCES XDISASMCORE_SOURCES)
    foreach(_pat ${_die_excluded_decoders})
        list(FILTER ${_var} EXCLUDE REGEX "${_pat}")
    endforeach()
endforeach()

set(SCAN_WASM_SOURCES
    ${SCAN_WASM_SRC}/WebFileDevice.cpp
    ${SCAN_WASM_SRC}/WebFileDevice.h
    ${SCAN_WASM_SRC}/Session.cpp
    ${SCAN_WASM_SRC}/Session.h
    ${SCAN_WASM_SRC}/bridge.cpp
    ${SCAN_WASM_SRC}/bridge_dispatch.cpp
    ${SCAN_WASM_SRC}/decoder_stubs.cpp
)

list(APPEND XFORMATS_SOURCES
    ${DIE_ROOT}/Formats/xiodevice.cpp
    ${DIE_ROOT}/Formats/xiodevice.h
)
list(REMOVE_DUPLICATES XFORMATS_SOURCES)

add_executable(scan_engine
    ${SCAN_WASM_SOURCES}
    ${XFORMATS_SOURCES}
    ${XSCANENGINE_SOURCES}
    ${SPECABSTRACT_SOURCES}
    ${XSTATICUNPACKER_SOURCES}
    ${XFILEINFO_SOURCES}
    ${XCAPSTONE_SOURCES}
    ${XCPPFILT_SOURCES}
    ${XMIME_SOURCES}
    ${XDISASMCORE_SOURCES}
    ${XARCHIVE_SOURCES}
    ${DIE_ROOT}/XExtractor/xextractor.cpp
    ${DIE_ROOT}/XDemangle/xdemangle.cpp
    ${DIE_ROOT}/XDemangle/xdemangle.h
)

target_include_directories(scan_engine PRIVATE
    ${SCAN_WASM_SRC}/qt-stubs
    ${SCAN_WASM_SRC}
    ${DIE_ROOT}/XScanEngine
    ${DIE_ROOT}/XScanEngine/modules
    ${DIE_ROOT}/Formats
    ${DIE_ROOT}/SpecAbstract
    ${DIE_ROOT}/XStaticUnpacker
    ${DIE_ROOT}/XFileInfo
    ${DIE_ROOT}/XCapstone
    ${DIE_ROOT}/XCppfilt
    ${DIE_ROOT}/XDemangle
    ${DIE_ROOT}/XMIME
    ${DIE_ROOT}/XDisasmCore
    ${DIE_ROOT}/XArchive
    ${DIE_ROOT}/XExtractor
    ${DIE_ROOT}/XOptions
    ${DIE_ROOT}/XYara/3rdparty/yara/src/include
)

target_link_libraries(scan_engine PRIVATE
    Qt6::Core
    capstone
    cppfilt
    bzip2
    lzma
    ppmd
    yara
)

set(EMCC_LINK_FLAGS
    "-Os"
    "-fexceptions"
    "-sUSE_ZLIB=1"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sINITIAL_MEMORY=67108864"
    "-sWASM_BIGINT=0"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=ScanEngine"
    "-sENVIRONMENT=worker,web"
    "-sFORCE_FILESYSTEM=1"
    "-sSTACK_SIZE=8MB"
    "-sASYNCIFY=0"
    "-sEMULATE_FUNCTION_POINTER_CASTS=1"
    "-sEXPORTED_RUNTIME_METHODS=ccall,cwrap,FS,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP8"
)

set(EXPORTED_FUNCTIONS_LIST
    "_die_create"
    "_die_destroy"
    "_die_set_signatures_root"
    "_die_open_session"
    "_die_close_session"
    "_die_session_jsclass"
    "_die_invoke"
    "_die_free_string"
    "_die_get_file_info"
    "_die_compute_hashes"
    "_die_compute_entropy"
    "_die_get_memory_map"
    "_die_get_format_struct"
    "_die_get_symbols"
    "_die_disasm_range"
    "_die_yara_scan"
    "_die_get_mime"
    "_die_extract"
    "_die_demangle"
    "_die_get_import_hash"
    "_die_get_certificates"
    "_malloc"
    "_free"
)

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/dist/bindings-manifest.json)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/dist/bindings-manifest.json _manifest)
    string(REGEX MATCHALL "\"die_[a-zA-Z0-9_]+\"" _hot_matches "${_manifest}")
    foreach(_match ${_hot_matches})
        string(REGEX REPLACE "\"" "" _name "${_match}")
        list(APPEND EXPORTED_FUNCTIONS_LIST "_${_name}")
    endforeach()
    list(REMOVE_DUPLICATES EXPORTED_FUNCTIONS_LIST)
endif()

string(REPLACE ";" "," EXPORTED_FUNCTIONS_CSV "${EXPORTED_FUNCTIONS_LIST}")
list(APPEND EMCC_LINK_FLAGS "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCTIONS_CSV}]")

string(JOIN " " EMCC_LINK_FLAGS_STR ${EMCC_LINK_FLAGS})
set_target_properties(scan_engine PROPERTIES
    LINK_FLAGS "${EMCC_LINK_FLAGS_STR}"
    SUFFIX ".js"
)

target_compile_options(scan_engine PRIVATE
    -Os
    -fexceptions
    -Wno-unused-parameter
    -Wno-deprecated-declarations
    -Wno-inconsistent-missing-override
)

target_compile_definitions(scan_engine PRIVATE USE_ARCHIVE)

target_precompile_headers(scan_engine PRIVATE ${SCAN_WASM_SRC}/all_formats.h)
