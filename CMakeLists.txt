# INFO:
# https://nanobind.readthedocs.io/en/latest/building.html
#
cmake_minimum_required(VERSION 3.15...3.27)
project(upa_url_py LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_VERSION VERSION_LESS 3.18)
  set(DEV_MODULE Development)
else()
  set(DEV_MODULE Development.Module)
endif()

find_package(Python 3.8
  COMPONENTS Interpreter ${DEV_MODULE} REQUIRED
  OPTIONAL_COMPONENTS Development.SABIModule)

find_package(nanobind CONFIG REQUIRED)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include_directories(ext)

nanobind_add_module(
  # Module name
  upa_url

  # Target the stable ABI for Python 3.12+, which reduces
  # the number of binary wheels that must be built. This
  # does nothing on older Python versions
  STABLE_ABI

  # Build libnanobind statically and merge it into the
  # extension (which itself remains a shared library)
  NB_STATIC

  # Source code
  src/upa_url_bind.cpp
  ext/upa/url.cpp
  ext/upa/public_suffix_list.cpp)

# Install directive for scikit-build-core
install(TARGETS upa_url LIBRARY DESTINATION upa_url)
