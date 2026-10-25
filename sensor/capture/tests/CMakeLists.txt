FetchContent_Declare(doctest
  URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.tar.gz
  URL_HASH SHA256=73381c7aa4dee704bd935609668cf41880ea7f19fa0504a200e13b74999c2d70
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(DOCTEST_NO_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(doctest)

set(FIXTURE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/fixtures")

# Unit tests: parser, address classification, aggregation, config.
add_executable(unit_tests
  test_main.cpp
  test_addresses.cpp
  test_packet_parser.cpp
  test_window_aggregator.cpp
  test_config.cpp)
target_link_libraries(unit_tests PRIVATE
  sentinel_core nlohmann_json::nlohmann_json doctest::doctest sentinel_warnings)
add_test(NAME unit COMMAND unit_tests)

# End-to-end: run the real binary in replay mode on each committed fixture
# and assert on the window files it publishes.
add_executable(fixture_tests test_main.cpp test_fixtures.cpp)
target_link_libraries(fixture_tests PRIVATE
  nlohmann_json::nlohmann_json doctest::doctest sentinel_warnings)
target_compile_definitions(fixture_tests PRIVATE
  SENTINEL_CAPTURE_BIN="$<TARGET_FILE:sentinel-capture>"
  SENTINEL_FIXTURE_DIR="${FIXTURE_DIR}")
add_dependencies(fixture_tests sentinel-capture)

foreach(fixture port_scan syn_flood benign)
  add_test(NAME replay_${fixture} COMMAND fixture_tests --test-case=${fixture})
endforeach()
