// =======================================================================
// test1.c
// Copyright (c) 2020 Nicolas Ivan Hamblenne
// =======================================================================

#include "ngc.h"
#include <stdio.h>

void ngc_debug(FILE*);

void tracer(void *block)
{
    void **data = block;
    ngc_mark(*data);
}

void *a = NULL;
void *b = NULL;
void **c = NULL;
void *d = NULL;

void trace_roots(void *dummy)
{
    ngc_mark(c);
}

int main()
{
    ngc_register_trace_function(ngc_trace_func1, tracer);
    ngc_register_root_tracer(trace_roots, NULL);
    a = ngc_alloc(10, ngc_dont_trace);
    ngc_set_root(a);
    b = ngc_alloc(20, ngc_dont_trace);
    ngc_set_root(b);
    c = ngc_alloc(123, ngc_trace_func1);
    *c = NULL;
    d = ngc_alloc(0xfff00, ngc_dont_trace);
    *c = a;
    ngc_unset_root(a);
    ngc_unset_root(b);

    ngc_debug(stdout);

    ngc_collect(true);
    ngc_debug(stdout);

    a = ngc_alloc(4, ngc_dont_trace);
    ngc_debug(stdout);
}
