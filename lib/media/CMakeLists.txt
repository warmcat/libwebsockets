include_directories(.)

add_subdirectory(transcode)
add_subdirectory(v4l2)
add_subdirectory(alsa)
if (LWS_WITH_ALSA)
	add_subdirectory(audio)
endif()

exports_to_parent_scope()
