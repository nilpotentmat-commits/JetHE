cmake_minimum_required(VERSION 3.20)
project(leveled_jet_comparison LANGUAGES CXX)
find_package(OpenFHE CONFIG REQUIRED)
add_executable(leveled_jet_comparison benchmark.cpp)
target_compile_features(leveled_jet_comparison PRIVATE cxx_std_17)
target_compile_definitions(leveled_jet_comparison PRIVATE
  OPENFHE_VERSION=${BASE_OPENFHE_VERSION})
target_include_directories(leveled_jet_comparison PRIVATE
  "${OpenFHE_INCLUDE}" "${OpenFHE_INCLUDE}/core"
  "${OpenFHE_INCLUDE}/pke" "${OpenFHE_INCLUDE}/binfhe")
target_link_libraries(leveled_jet_comparison PRIVATE OPENFHEpke)
if(WIN32)
  target_link_libraries(leveled_jet_comparison PRIVATE psapi)
  get_filename_component(MINGW_RUNTIME_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
  foreach(dll libOPENFHEcore.dll libOPENFHEpke.dll libOPENFHEbinfhe.dll)
    add_custom_command(TARGET leveled_jet_comparison POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${OpenFHE_LIBDIR}/${dll}" "$<TARGET_FILE_DIR:leveled_jet_comparison>")
  endforeach()
  foreach(dll libgcc_s_seh-1.dll libdl.dll libgomp-1.dll libstdc++-6.dll libwinpthread-1.dll)
    if(EXISTS "${MINGW_RUNTIME_DIR}/${dll}")
      add_custom_command(TARGET leveled_jet_comparison POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${MINGW_RUNTIME_DIR}/${dll}" "$<TARGET_FILE_DIR:leveled_jet_comparison>")
    endif()
  endforeach()
endif()
enable_testing()
add_test(NAME plaintext_contract COMMAND leveled_jet_comparison --self-test)
