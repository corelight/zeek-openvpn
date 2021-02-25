
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginopenvpn)

include(ZeekPlugin)

zeek_plugin_begin(zeek openvpn)
zeek_plugin_cc(src/Plugin.cc src/OpenVPN.cc src/OpenVPNHMAC.cc)
zeek_plugin_bif(src/types.bif src/events.bif)
zeek_plugin_pac(src/openvpntcphmac.pac src/openvpntcphmac-protocol.pac src/openvpntcphmac-analyzer.pac)
zeek_plugin_pac(src/openvpntcp.pac src/openvpntcp-protocol.pac src/openvpntcp-analyzer.pac)
zeek_plugin_pac(src/openvpnhmac.pac src/openvpnhmac-protocol.pac src/openvpnhmac-analyzer.pac)
zeek_plugin_pac(src/openvpn.pac src/openvpn-protocol.pac src/openvpn-analyzer.pac)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
