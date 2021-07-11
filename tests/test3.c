// =======================================================================
// test3.c
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

void finalizer(void *block)
{
    printf("Finalizing\n");
}

int main()
{
    struct ngc_policy_info policyInfo = { tracer, finalizer };
    void *a = ngc_alloc(10, ngc_dont_trace);
    ngc_set_root(a);
    void *b = ngc_alloc(20, ngc_dont_trace);
    ngc_set_root(b);
    void **c = ngc_alloc_with_info(123, &policyInfo);
    *c = NULL;
    ngc_set_root(c);
    void *d = ngc_alloc(0xfff00, ngc_dont_trace);
    *c = a;
    ngc_unset_root(a);
    ngc_unset_root(b);
    ngc_debug(stdout);

    ngc_collect(true);
    ngc_debug(stdout);

    a = ngc_alloc(4, ngc_dont_trace);
    ngc_debug(stdout);

    ngc_unset_root(c);
    ngc_collect(true);
    ngc_debug(stdout);
}
