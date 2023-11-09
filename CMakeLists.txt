cmake_minimum_required(VERSION 2.8)
project(tunnel)
set(TUNNEL_TARGET ON)
set(TUNNELD_TARGET ON)
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

# x21 compiler
# set(X21_COMPILE ON)
option(X21_COMPILE "build aarch64 client target" OFF)
if(X21_COMPILE)
	set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
	set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
	# add_executable(test test/test.c)
	set(TUNNEL_TARGET ON)
	set(TUNNELD_TARGET OFF)
endif()


#tunnel
if(TUNNEL_TARGET)
add_executable(tunnel tunnel/src/tunnel.c tunnel/inc/tunnel.h /
				common/inc/iniparser.h common/inc/dictionary.h common/inc/common.h
				common/src/iniparser.c common/src/dictionary.c common/src/common.c	/
				)
target_include_directories(tunnel PUBLIC
${CMAKE_CURRENT_SOURCE_DIR}/tunnel/inc
${CMAKE_CURRENT_SOURCE_DIR}/common/inc
)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tunnel/etc/tunnel.conf DESTINATION ${CMAKE_BINARY_DIR}/)
endif()

#tunneld
if(TUNNELD_TARGET)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib/zlog/lib)
add_executable(tunneld tunneld/src/tunneld.c tunneld/inc/tunneld.h /
				common/inc/iniparser.h common/inc/dictionary.h common/inc/common.h	/
				common/src/iniparser.c common/src/dictionary.c common/src/common.c	/
				)
target_include_directories(tunneld PUBLIC
${CMAKE_CURRENT_SOURCE_DIR}/lib/zlog/include
${CMAKE_CURRENT_SOURCE_DIR}/tunneld/inc
${CMAKE_CURRENT_SOURCE_DIR}/common/inc
)
target_link_libraries(tunneld 
	${CMAKE_CURRENT_SOURCE_DIR}/lib/zlog/lib/libzlog.a
	pthread
	)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tunneld/etc/tunneld.conf DESTINATION ${CMAKE_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tunneld/etc/zlog.conf DESTINATION ${CMAKE_BINARY_DIR}/)
endif()