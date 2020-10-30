#ifndef LIBNGC_NGC_H
#define LIBNGC_NGC_H

/* =======================================================================
 * ngc.h
 * Copyright (c) 2020 Nicolas Ivan Hamblenne
 * =======================================================================
 */

#include <stdlib.h>
#include <stdbool.h>

/** type of functions used to start the tracing of root objects.
 *  The void* parameter is a user data given at registration time.
 */
typedef void (*ngc_root_tracer)(void*);

/** type of functions used to trace allocated object.  Only one
 *  such function can be registered.
 */
typedef void (*ngc_trace_function)(void*);

/** policy to apply for tracing the result of an allocation.
 */
enum ngc_policy {
    ngc_dont_trace = 1, /*<< allocated block should not be traced */
    ngc_trace_func      /*<< allocated block should be traced by the global trace function */
};

/** allocation function.
 */
void* ngc_alloc(size_t, enum ngc_policy);

/** register a function used to trace root objects.  The void*
 *  parameter will be given back to the function. Several roots
 *  tracers can be registered or the same function can be registered
 *  several times with the same or different user_data.
 */
void ngc_register_root_tracer(ngc_root_tracer, void*);

/** register a function used to trace allocated memory.  Only one such
 *  function can be registered.
 */
void ngc_register_trace_function(ngc_trace_function);

/** mark allocated memory as living. Has to be called by registered
 *  tracers.
 */
void ngc_mark(void*);

/** mark allocated memory as root.  This is designed to be used
 *  temporarily for roots which are difficult to traverse with
 *  registered root tracers. A memory block can be marked several
 *  times as root, it will then need to be unset as many times.
 */
void ngc_set_root(void*);

/** unmark allocated memory as root.
 */
void ngc_unset_root(void*);

/** trigger a garbage collection.  If the bool argument is true,
 *  the collection happens unconditionally, if it is false, it
 *  happens only if enough memory has been allocated since the last
 *  collection cycle.
 */
void ngc_collect(bool);

#endif
