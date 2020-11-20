# The strategy is to only export to PARENT_SCOPE
#
#  - changes to LIB_LIST
#  - includes via include_directories
#
# and keep everything else private

include_directories(.)

if (LWS_WITH_EVLIB_PLUGINS)

    create_evlib_plugin(
            evlib_sd
            sdevent.c)

else()

    list(APPEND SOURCES
            event-libs/sdevent/sdevent.c)

endif()

#
# Keep explicit parent scope exports at end
#

exports_to_parent_scope()
