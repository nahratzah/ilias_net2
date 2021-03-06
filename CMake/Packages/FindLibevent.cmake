# - Try to find ev event library.
# Once done, this will define
#
#  EV_FOUND - system has ev
#  EV_INCLUDE_DIRS - the ev include dirs
#  EV_LIBRARIES - link these to use ev

include (FindPackageHandleStandardArgs)

# Import LIBEVENT_HOME from environment.
set (LIBEVENT_PREFIX_PATH ${LIBEVENT_HOME})
set (LIBEVENT_LIBRARY_NAMES event_core event_pthreads)

find_path (LIBEVENT_INCLUDE_DIRS event2/event.h PATH_SUFFIXES include DOC "The path to the directory containing event.h")
find_library (LIBEVENT_LIBRARIES NAMES event_core PATH_SUFFIXES lib64 lib lib32 DOC "The libevent core library.")

find_library (LIBEVENT_thread_LIBRARY NAMES event_pthreads PATH_SUFFIXES lib64 lib lib32 DOC "The libevent thread library.")
if (NOT LIBEVENT_thread_LIBRARY-NOTFOUND)
	list (APPEND LIBEVENT_LIBRARIES ${LIBEVENT_thread_LIBRARY})
endif (NOT LIBEVENT_thread_LIBRARY-NOTFOUND)

find_package_handle_standard_args (libEvent DEFAULT_MSG LIBEVENT_LIBRARIES LIBEVENT_INCLUDE_DIRS)
