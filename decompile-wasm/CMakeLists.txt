cmake_minimum_required(VERSION 3.21)
project(decompile_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR
        "decompile-wasm/CMakeLists.txt is for Emscripten builds only. "
        "Run via decompile-wasm/build.sh inside the dev container.")
endif()

set(GHIDRA_ROOT  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ghidra)
set(DECOMP_DIR   ${GHIDRA_ROOT}/Ghidra/Features/Decompiler/src/decompile/cpp)
set(BRIDGE_SRC   ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(NOT EXISTS ${DECOMP_DIR}/libdecomp.cc)
    message(FATAL_ERROR
        "Ghidra submodule missing or empty at ${GHIDRA_ROOT}. "
        "Run: git submodule update --init --recursive in the parent repo.")
endif()

set(GHIDRA_SOURCES
    xml.cc marshal.cc space.cc float.cc address.cc pcoderaw.cc translate.cc
    opcodes.cc globalcontext.cc
    capability.cc architecture.cc options.cc graph.cc cover.cc block.cc cast.cc
    typeop.cc database.cc cpool.cc comment.cc stringmanage.cc modelrules.cc
    fspec.cc action.cc loadimage.cc grammar.cc varnode.cc op.cc type.cc
    variable.cc varmap.cc jumptable.cc emulate.cc emulateutil.cc flow.cc
    userop.cc expression.cc multiprecision.cc funcdata.cc funcdata_block.cc
    funcdata_op.cc funcdata_varnode.cc unionresolve.cc pcodeinject.cc heritage.cc
    prefersplit.cc rangeutil.cc ruleaction.cc subflow.cc blockaction.cc merge.cc
    double.cc transform.cc constseq.cc bitfield.cc coreaction.cc condexe.cc
    override.cc dynamic.cc crc32.cc prettyprint.cc printlanguage.cc printc.cc
    printjava.cc memstate.cc opbehavior.cc paramid.cc signature.cc
    sleigh.cc sleigh_arch.cc inject_sleigh.cc pcodeparse.cc pcodecompile.cc
    sleighbase.cc slghsymbol.cc slghpatexpress.cc slghpattern.cc semantics.cc
    context.cc slaformat.cc compression.cc filemanage.cc
    string_ghidra.cc
    libdecomp.cc
)
list(TRANSFORM GHIDRA_SOURCES PREPEND "${DECOMP_DIR}/")

add_executable(decompile_engine
    ${GHIDRA_SOURCES}
    ${BRIDGE_SRC}/WebLoadImage.cpp
    ${BRIDGE_SRC}/WebArchitecture.cpp
    ${BRIDGE_SRC}/bridge.cpp
)

target_include_directories(decompile_engine PRIVATE ${DECOMP_DIR} ${BRIDGE_SRC})

target_compile_options(decompile_engine PRIVATE -Os -fexceptions -w -sUSE_ZLIB=1)

set(EMCC_LINK_FLAGS
    "-Os"
    "-fexceptions"
    "-sUSE_ZLIB=1"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sINITIAL_MEMORY=67108864"
    "-sSTACK_SIZE=8MB"
    "-sWASM_BIGINT=1"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=DecompileEngine"
    "-sENVIRONMENT=worker,web"
    "-sFORCE_FILESYSTEM=1"
    "-sEXPORTED_RUNTIME_METHODS=ccall,cwrap,FS,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP8"
    "-sEXPORTED_FUNCTIONS=[_decomp_init,_decomp_add_spec_dir,_decomp_create,_decomp_add_region,_decomp_add_symbol,_decomp_add_import,_decomp_add_string,_decomp_add_readonly,_decomp_parse_c,_decomp_decompile,_decomp_call_targets,_decomp_free_string,_decomp_destroy,_malloc,_free]"
)
string(JOIN " " EMCC_LINK_FLAGS_STR ${EMCC_LINK_FLAGS})
set_target_properties(decompile_engine PROPERTIES
    LINK_FLAGS "${EMCC_LINK_FLAGS_STR}"
    SUFFIX ".js")
