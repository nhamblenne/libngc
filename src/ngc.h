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

/** type of functions used to trace allocated object.  Four global
 *  tracer can be registered, and it is possible to specify a block
 *  specific tracer at allocation time.
 */
typedef void (*ngc_trace_function)(void*);

/** type of functions used to finalize allocated object.
 */
typedef void (*ngc_finalize_function)(void*);

/** policy to apply for tracing the result of an allocation.
 */
enum ngc_policy {
    ngc_free_block,     /*<< used to mark free block */
    ngc_dont_trace,     /*<< allocated block should not be traced */
    ngc_trace_func1,    /*<< allocated block should be traced by the first global trace function */
    ngc_trace_func2,    /*<< allocated block should be traced by the second global trace function */
    ngc_trace_func3,    /*<< allocated block should be traced by the third global trace function */
    ngc_trace_func4,    /*<< allocated block should be traced by the fourth global trace function */
    ngc_block_tracer,   /*<< allocated block should be traced by the provided trace function */
    ngc_extended_policy /*<< allocated block should be handled by the provided policy descriptor */
};

struct ngc_policy_info {
    ngc_trace_function    tracer;
    ngc_finalize_function finalizer;
};

/** allocation function.
 */
void *ngc_alloc(size_t, enum ngc_policy);
void *ngc_alloc_with_tracer(size_t sz, ngc_trace_function);
void *ngc_alloc_with_info(size_t sz, struct ngc_policy_info *policy_info);

/** register a function used to trace root objects.  The void*
 *  parameter will be given back to the function. Several roots
 *  tracers can be registered or the same function can be registered
 *  several times with the same or different user_data.
 */
void ngc_register_root_tracer(ngc_root_tracer, void*);

/** register a function used to trace allocated memory.  Four such
 *  functions can be registered, they are identified by the policy
 *  to use when allocating a block they should trace.
 */
void ngc_register_trace_function(enum ngc_policy, ngc_trace_function);

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
