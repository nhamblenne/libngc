/* =======================================================================
 * ngc.c
 * Copyright (c) 2020 Nicolas Ivan Hamblenne
 * =======================================================================
 */

#include "ngc.h"

#include <stdio.h>
#include <memory.h>
#include <stdint.h>

struct block_header {
    size_t size;
    struct block_header *next;
};

struct root_tracer_record {
    ngc_root_tracer tracer;
    void* user_data;
};

#define SET_MARK(sz)           ((sz)  |   1U)
#define CLEAR_MARK(sz)         ((sz)  &  ~1U)
#define IS_MARKED(sz)          (((sz) &   1U) == 1U)
#define SET_POLICY(sz, policy) (((sz) & ~14U) | ((policy) << 1U))
#define GET_POLICY(sz)         (((sz) &  14U) >> 1U)
#define CLEAR_ALL(sz)          ((sz)  & ~15U)

static const size_t header_size = sizeof(struct block_header);
typedef char header_size_must_be_16[sizeof(struct block_header) == 16 ? 1 : -1];
static const size_t minimum_chunk_size = 1024 * 1024;

static struct block_header *first_chunk = NULL;
static struct block_header *last_chunk = NULL;

static struct block_header *free_list = NULL;
static struct block_header *prev_free = NULL;
static struct block_header *current_free = NULL;
static struct block_header *last_free = NULL;

static struct block_header *grey_list = NULL;

static size_t num_roots = 0;
static size_t max_roots = 0;
static const size_t init_max_roots = 16;
static struct block_header **roots = NULL;

static ngc_trace_function tracer_function = NULL;
static size_t num_root_tracers = 0;
static size_t max_root_tracers = 0;
static const size_t init_max_root_tracers = 16;
static struct root_tracer_record *root_tracers = NULL;

static void *get_core(size_t sz)
{
    void *result = malloc(sz);
    if (result == NULL) {
        fprintf(stderr, "\nOut of memory\n");
        exit(EXIT_FAILURE);
    }
    return result;
}

static void *allocate(size_t sz, enum ngc_policy policy)
{
    struct block_header *current = current_free;
    struct block_header *prev = prev_free;

    const size_t num_headers = (sz + header_size - 1) / header_size;
    sz = num_headers * header_size;

    if (current == NULL) {
        current = free_list;
        current_free = free_list;
        prev = NULL;
    }

    if (current != NULL) {
        do {
            if (current->size >= sz + 3 * header_size) {
                struct block_header *new_block = current + num_headers + 1;
                new_block->size = current->size - sz - header_size;
                new_block->next = current->next;
                current->size = sz + header_size;
                current->next = new_block;
                if (current == last_free) {
                    last_free = new_block;
                }
            }
            if (current->size >= sz + header_size) {
                if (current == last_free) {
                    last_free = prev;
                }
                if (prev == NULL) {
                    free_list = current->next;
                } else {
                    free_list->next = current->next;
                }
                prev_free = prev;
                current_free = current->next;
                current->next = NULL;
                current->size = SET_POLICY(current->size, policy);
                return current + 1;
            }
            prev = current;
            current = current->next;
            if (current == NULL) {
                prev = NULL;
                current = free_list;
            }
        } while (current != current_free);
    }

    return NULL;
}

static void expand_memory(size_t sz)
{
    size_t chunk_size = (minimum_chunk_size + sz + 2 * header_size + 15) / minimum_chunk_size * minimum_chunk_size;
    struct block_header *new_chunk = get_core(chunk_size);
    new_chunk->size = chunk_size;
    new_chunk->next = NULL;
    if (last_chunk == NULL) {
        first_chunk = new_chunk;
    } else {
        last_chunk->next = new_chunk;
    }
    last_chunk = new_chunk;

    struct block_header *new_block = new_chunk + 1;
    size_t block_size = chunk_size - header_size;
    uintptr_t block_ptr = (uintptr_t)new_block;
    if (block_ptr % 16 != 0) {
        uintptr_t offset = 16 - block_ptr % 16;
        block_size -= offset;
        block_ptr += offset;
        new_block = (struct block_header*)block_ptr;
    }
    new_block->size = block_size;
    new_block->next = NULL;
    if (last_free == NULL) {
        free_list = new_block;
    } else {
        last_free->next = new_block;
    }
    prev_free = last_free;
    current_free = new_block;
    last_free = new_block;
}

void *ngc_alloc(size_t sz, enum ngc_policy policy)
{
    void *result = allocate(sz, policy);

    if (result == NULL) {
        ngc_collect(true);
        result = allocate(sz, policy);
    }

    if (result == NULL) {
        expand_memory(sz);
        result = allocate(sz, policy);
    }

    return result;
}

void ngc_register_root_tracer(ngc_root_tracer tracer, void *user_data)
{
    if (num_root_tracers == max_root_tracers) {
        size_t new_max_root_tracers = max_root_tracers == 0 ? init_max_root_tracers : 2 * max_root_tracers;
        struct root_tracer_record *new_root_tracers = get_core(new_max_root_tracers * sizeof(ngc_root_tracer));
        memcpy(new_root_tracers, root_tracers, max_root_tracers * sizeof(struct root_tracer_record));
        free(root_tracers);
        root_tracers = new_root_tracers;
        max_root_tracers = new_max_root_tracers;
    }
    root_tracers[num_root_tracers].tracer = tracer;
    root_tracers[num_root_tracers].user_data = user_data;
    ++num_root_tracers;
}

void ngc_register_trace_function(ngc_trace_function tracer)
{
    tracer_function = tracer;
}

void ngc_mark(void *block)
{
    if (block == NULL) {
        return;
    }
    struct block_header *header = block;
    --header;
    if (! IS_MARKED(header->size)) {
        header->size = SET_MARK(header->size);
        switch (GET_POLICY(header->size)) {
            case ngc_dont_trace:
                break;
            case ngc_trace_func:
                header->next = grey_list;
                grey_list = header;
        }
    }
}

void ngc_set_root(void *block)
{
    struct block_header *header = block;
    if (num_roots == max_roots) {
        size_t new_max_roots = max_roots == 0 ? init_max_roots : 2 * max_roots;
        struct block_header **new_roots = get_core(new_max_roots * header_size);
        memcpy(new_roots, roots, max_roots * header_size);
        free(roots);
        roots = new_roots;
        max_roots = new_max_roots;
    }
    roots[num_roots++] = header;
}

void ngc_unset_root(void *block)
{
    struct block_header *header = block;
    for (size_t i = num_roots; i-- > 0; ) {
        if (roots[i] == header) {
            roots[i] = roots[--num_roots];
            break;
        }
    }
}

static void mark_grey_list()
{
    while (grey_list != NULL) {
        struct block_header *header = grey_list;
        grey_list = header->next;
        switch (GET_POLICY(header->size)) {
            case ngc_dont_trace:
                break;
            case ngc_trace_func:
                if (tracer_function != NULL) {
                    tracer_function(header + 1);
                }
                break;
        }
    }
}

static void mark_all()
{
    for (size_t i = 0; i < max_root_tracers; ++i) {
        root_tracers[i].tracer(root_tracers[i].user_data);
        mark_grey_list();
    }
    for (size_t i = 0; i < num_roots; ++i) {
        ngc_mark(roots[i]);
        mark_grey_list();
    }
}

static void sweep_all()
{
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            if (IS_MARKED(block->size)) {
                block->size = CLEAR_MARK(block->size);
            } else if (GET_POLICY(block->size) != 0) {
                block->size = CLEAR_ALL(block->size);
                block->next = NULL;
                if (last_free == NULL) {
                    free_list = block;
                } else {
                    last_free->next = block;
                }
                last_free = block;
            }
        }
    }
}

void ngc_collect(bool force)
{
    mark_all();
    sweep_all();
}

void ngc_debug(FILE *f)
{
    fprintf(f, "\nNGC Memory map\n\n");
    fprintf(f, "header_size:        %#zx\n", header_size);
    fprintf(f, "minimum_chunk_size: %#zx\n\n", minimum_chunk_size);

    fprintf(f, "first_chunk:  %18p\n", first_chunk);
    fprintf(f, "last_chunk:   %18p\n", last_chunk);
    fprintf(f, "free_list:    %18p\n", free_list);
    fprintf(f, "prev_free:    %18p\n", prev_free);
    fprintf(f, "current_free: %18p\n", current_free);
    fprintf(f, "last_free:    %18p\n\n", last_free);

    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        fprintf(f, "Chunk at %18p, size: %#8zx, next: %18p\n", chunk, chunk->size, chunk->next);
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            fprintf(f, "Block at %18p, size: %#8zx, next: %18p\n", block, block->size, block->next);
        }
        fprintf(f, "\n");
    }
}
