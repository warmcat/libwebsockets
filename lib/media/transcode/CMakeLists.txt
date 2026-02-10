if (LWS_WITH_TRANSCODE)
	list(APPEND SOURCES media/transcode/transcode.c)
endif()

exports_to_parent_scope()
