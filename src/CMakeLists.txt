INCLUDE_DIRECTORIES(../include)
set(LINK_DIR ../lib)
link_directories(${LINK_DIR})
add_executable(main main.cu)

target_link_libraries(main GPUKEYWORDPIR)
