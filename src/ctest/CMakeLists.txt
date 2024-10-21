

add_executable(test_bech32 test_bech32.c)
target_include_directories(test_bech32 PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_bech32 PRIVATE wallycore)
add_test(test_bech32 test_bech32)

if(NOT WIN32)
    add_executable(test_clear test_clear.c)
    target_include_directories(test_clear PRIVATE ${CMAKE_BINARY_DIR})
    target_link_libraries(test_clear PRIVATE wallycore pthread)
    add_test(test_clear test_clear)
endif()

add_executable(test_coinselection test_coinselection.c)
target_include_directories(test_coinselection PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_coinselection PRIVATE wallycore)
add_test(test_coinselection test_coinselection)

add_executable(test_descriptor test_descriptor.c)
target_include_directories(test_descriptor PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_descriptor PRIVATE wallycore)
add_test(test_descriptor test_descriptor)

add_executable(test_elements_tx test_elements_tx.c)
target_include_directories(test_elements_tx PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_elements_tx PRIVATE wallycore)
add_test(test_elements_tx test_elements_tx)

add_executable(test_psbt test_psbt.c)
target_include_directories(test_psbt PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_psbt PRIVATE wallycore)
add_test(test_psbt test_psbt)

add_executable(test_psbt_limits test_psbt_limits.c)
target_include_directories(test_psbt_limits PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(test_psbt_limits PRIVATE wallycore)
add_test(test_psbt_limits test_psbt_limits)
