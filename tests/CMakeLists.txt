enable_testing()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE test_sources CONFIGURE_DEPENDS "*.cpp" "*.c")

add_executable(${PROJECT_NAME}_tests ${test_sources})
target_link_libraries(${PROJECT_NAME}_tests PRIVATE ${PROJECT_NAME}-deps googletest)
target_include_directories(${PROJECT_NAME}_tests PRIVATE ${CMAKE_SOURCE_DIR}/mod_http3/include)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME}_tests)

add_custom_target(tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --output-junit ctest-results.xml
    DEPENDS ${PROJECT_NAME}_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

install(TARGETS ${PROJECT_NAME}_tests RUNTIME DESTINATION bin)
