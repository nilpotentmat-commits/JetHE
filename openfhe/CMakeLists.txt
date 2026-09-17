cmake_minimum_required(VERSION 3.20)
project(jethe_openfhe_adapters LANGUAGES CXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The measured adapter uses Linux affinity and resource APIs. Build on Linux or inside WSL.")
endif()
find_package(OpenFHE 1.5.1 EXACT CONFIG REQUIRED)
add_executable(openfhe_matched_w0 src/openfhe_w0.cpp)
target_compile_features(openfhe_matched_w0 PRIVATE cxx_std_17)
target_compile_definitions(openfhe_matched_w0 PRIVATE OPENFHE_VERSION=${BASE_OPENFHE_VERSION})
target_include_directories(openfhe_matched_w0 PRIVATE
  "${OpenFHE_INCLUDE}" "${OpenFHE_INCLUDE}/core"
  "${OpenFHE_INCLUDE}/pke" "${OpenFHE_INCLUDE}/binfhe")
target_link_libraries(openfhe_matched_w0 PRIVATE OPENFHEpke)
set_target_properties(openfhe_matched_w0 PROPERTIES
  BUILD_RPATH "${OpenFHE_LIBDIR};${CMAKE_BUILD_RPATH}")

# The fixture export needs no OpenFHE API; it shares the measured input generator.
add_executable(export_fixture src/export_fixture.cpp)
target_compile_features(export_fixture PRIVATE cxx_std_17)
