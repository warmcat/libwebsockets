if (LWS_WITH_V4L2)
	list(APPEND SOURCES media/v4l2/v4l2.c)
endif()

exports_to_parent_scope()
