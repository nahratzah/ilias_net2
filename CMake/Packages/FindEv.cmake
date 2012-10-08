# - Try to find ev event library.
# Once done, this will define
#
#  EV_FOUND - system has ev
#  EV_INCLUDE_DIR - the ev include dir
#  EV_LIBRARIES - link these to use ev

include (FindPackageHandleStandardArgs)

# Import EV_HOME from environment.
set (EV_PREFIX_PATH ${EV_HOME})
set (EV_LIBRARY_NAMES ev)

find_path (EV_INCLUDE_DIR ev.h PATH_SUFFIXES include DOC "The path to the directory containing ev.h")
find_library (EV_LIBRARIES NAMES ev PATH_SUFFIXES lib64 lib lib32 DOC "The ev library.")

find_package_handle_standard_args (EV DEFAULT_MSG EV_LIBRARIES EV_INCLUDE_DIR)
