/*
 * Copyright 2013 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#if !defined (BSON_INSIDE) && !defined (BSON_COMPILATION)
#error "Only <bson.h> can be included directly."
#endif


#ifndef BSON_VERSION_H
#define BSON_VERSION_H


/**
 * BSON_MAJOR_VERSION:
 *
 * BSON major version component (e.g. 1 if %BSON_VERSION is 1.2.3)
 */
#define BSON_MAJOR_VERSION (1)


/**
 * BSON_MINOR_VERSION:
 *
 * BSON minor version component (e.g. 2 if %BSON_VERSION is 1.2.3)
 */
#define BSON_MINOR_VERSION (1)


/**
 * BSON_MICRO_VERSION:
 *
 * BSON micro version component (e.g. 3 if %BSON_VERSION is 1.2.3)
 */
#define BSON_MICRO_VERSION (11)


/**
 * BSON_VERSION:
 *
 * BSON version.
 */
#define BSON_VERSION (1.1.11)


/**
 * BSON_VERSION_S:
 *
 * BSON version, encoded as a string, useful for printing and
 * concatenation.
 */
#define BSON_VERSION_S "1.1.11"


/**
 * BSON_VERSION_HEX:
 *
 * BSON version, encoded as an hexadecimal number, useful for
 * integer comparisons.
 */
#define BSON_VERSION_HEX (BSON_MAJOR_VERSION << 24 | \
                          BSON_MINOR_VERSION << 16 | \
                          BSON_MICRO_VERSION << 8)


/**
 * BSON_CHECK_VERSION:
 * @major: required major version
 * @minor: required minor version
 * @micro: required micro version
 *
 * Compile-time version checking. Evaluates to %TRUE if the version
 * of BSON is greater than the required one.
 */
#define BSON_CHECK_VERSION(major,minor,micro)   \
        (BSON_MAJOR_VERSION > (major) || \
         (BSON_MAJOR_VERSION == (major) && BSON_MINOR_VERSION > (minor)) || \
         (BSON_MAJOR_VERSION == (major) && BSON_MINOR_VERSION == (minor) && \
          BSON_MICRO_VERSION >= (micro)))


/**
 * bson_get_major_version:
 *
 * Helper function to return the runtime major version of the library.
 */
int bson_get_major_version (void);


/**
 * bson_get_minor_version:
 *
 * Helper function to return the runtime minor version of the library.
 */
int bson_get_minor_version (void);


/**
 * bson_get_micro_version:
 *
 * Helper function to return the runtime micro version of the library.
 */
int bson_get_micro_version (void);


#endif /* BSON_VERSION_H */
