configure_file(config.xml.in config.xml @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.xml icon.jpg DESTINATION ${APPDIR})
install(DIRECTORY htdocs etc hidden DESTINATION ${APPDIR})
