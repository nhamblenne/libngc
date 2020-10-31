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

int main()
{
    ngc_register_trace_function(ngc_trace_func1, tracer);
    void *a = ngc_alloc(10, ngc_dont_trace);
    ngc_set_root(a);
    void *b = ngc_alloc(20, ngc_dont_trace);
    ngc_set_root(b);
    void **c = ngc_alloc(123, ngc_trace_func1);
    ngc_set_root(c);
    void *d = ngc_alloc(0xfff00, ngc_dont_trace);
    printf("a = %18p\n", a);
    printf("b = %18p\n", b);
    printf("c = %18p\n", c);
    printf("d = %18p\n", d);
    *c = a;
    ngc_unset_root(a);
    ngc_unset_root(b);
    ngc_debug(stdout);
    ngc_collect(true);
    ngc_debug(stdout);
    a = ngc_alloc(4, ngc_dont_trace);
    printf("a = %18p\n", a);
    ngc_debug(stdout);
}
