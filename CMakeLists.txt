cmake_minimum_required(VERSION 3.20)
project(caraxes VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(CAPSTONE QUIET IMPORTED_TARGET capstone)
endif()
if(NOT CAPSTONE_FOUND)
  find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
  find_library(CAPSTONE_LIBRARY NAMES capstone)
  if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone is required (install capstone development files)")
  endif()
  add_library(capstone::capstone UNKNOWN IMPORTED)
  set_target_properties(capstone::capstone PROPERTIES
    IMPORTED_LOCATION "${CAPSTONE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIR}")
  set(CAPSTONE_TARGET capstone::capstone)
else()
  set(CAPSTONE_TARGET PkgConfig::CAPSTONE)
endif()

add_library(caraxes_elf
  src/loader/elf/elf.cpp
)
add_library(caraxes_analysis src/analysis/analysis.cpp)
add_library(caraxes_disasm src/disasm/disasm.cpp)
add_library(caraxes_decompiler
  src/decompiler/decompiler.cpp
  src/decompiler/project.cpp
)
target_include_directories(caraxes_analysis PUBLIC src)
target_compile_options(caraxes_analysis PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(caraxes_analysis PUBLIC caraxes_disasm)
target_include_directories(caraxes_elf PUBLIC src)
target_compile_options(caraxes_elf PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(caraxes_disasm PUBLIC src)
target_compile_options(caraxes_disasm PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(caraxes_disasm PUBLIC caraxes_elf ${CAPSTONE_TARGET})
target_include_directories(caraxes_decompiler PUBLIC src)
target_compile_options(caraxes_decompiler PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(caraxes_decompiler PUBLIC caraxes_disasm)

add_executable(caraxes src/main.cpp)
target_compile_options(caraxes PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(caraxes PRIVATE caraxes_elf caraxes_disasm caraxes_analysis caraxes_decompiler)
add_executable(caraxes-analysis src/analysis/main.cpp)
target_link_libraries(caraxes-analysis PRIVATE caraxes_analysis caraxes_elf)
add_executable(caraxes-disasm src/disasm/main.cpp)
target_link_libraries(caraxes-disasm PRIVATE caraxes_disasm)

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_executable(caraxes_elf_tests tests/elf_loader_test.cpp)
  target_link_libraries(caraxes_elf_tests PRIVATE caraxes_elf)
  add_test(NAME elf_loader COMMAND caraxes_elf_tests)
  add_executable(caraxes_analysis_tests tests/analysis_test.cpp)
  target_link_libraries(caraxes_analysis_tests PRIVATE caraxes_analysis)
  add_test(NAME analysis COMMAND caraxes_analysis_tests)
  add_executable(caraxes_disasm_tests tests/disasm_test.cpp)
  target_link_libraries(caraxes_disasm_tests PRIVATE caraxes_disasm)
  add_test(NAME disasm COMMAND caraxes_disasm_tests)
  add_executable(caraxes_decompiler_tests tests/decompiler_test.cpp)
  target_link_libraries(caraxes_decompiler_tests PRIVATE caraxes_decompiler caraxes_analysis)
  add_test(NAME decompiler COMMAND caraxes_decompiler_tests)
  add_test(NAME roundtrip
    COMMAND Python3::Interpreter
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/roundtrip_test.py"
      "$<TARGET_FILE:caraxes>"
      "${CMAKE_CURRENT_SOURCE_DIR}/hello.c")
endif()
