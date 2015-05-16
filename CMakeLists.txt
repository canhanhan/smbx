
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Custom SMB)
bro_plugin_cc(src/Plugin.cc src/Handler.cc src/SMBx.cc src/Analyzer.cc)
#bro_plugin_bif(src/events.bif)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()
