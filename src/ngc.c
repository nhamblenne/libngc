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

union extended_info {
    ngc_trace_function trace_function;
    struct ngc_policy_info* policy_info;
};

struct extended_header {
    struct block_header header;
    size_t size;
    union extended_info info;
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
typedef char extended_header_size_must_be_32[sizeof(struct extended_header) == 32 ? 1 : -1];
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

static ngc_trace_function tracer_functions[ngc_trace_func4 - ngc_trace_func1 + 1] = { NULL };
static size_t num_root_tracers = 0;
static size_t max_root_tracers = 0;
static const size_t init_max_root_tracers = 16;
static struct root_tracer_record *root_tracers = NULL;

static size_t allocated = 0;
static size_t available = 0;
static size_t available_after_last_collect = 0;

static void *get_core(size_t sz)
{
    void *result = malloc(sz);
    if (result == NULL) {
        fprintf(stderr, "\nOut of memory\n");
        exit(EXIT_FAILURE);
    }
    return result;
}

static void *allocate(size_t sz, enum ngc_policy policy, union extended_info policy_info)
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

    size_t header_overhead = 1;
    if (policy > ngc_trace_func4) {
        ++header_overhead;
    }
    if (current != NULL && available >= sz + header_overhead) {
        do {
            if (current->size >= sz + (header_overhead + 2) * header_size) {
                struct block_header *new_block = current + num_headers + header_overhead;
                new_block->size = current->size - sz - header_overhead * header_size;
                new_block->next = current->next;
                current->size = sz + header_size * header_overhead;
                current->next = new_block;
                if (current == last_free) {
                    last_free = new_block;
                }
            }
            if (current->size >= sz + header_size * header_overhead) {
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
                available -= CLEAR_ALL(current->size);
                if (policy <= ngc_trace_func4) {
                    return current + 1;
                } else {
                    struct extended_header *block = (struct extended_header *) current;
                    block->size = current->size;
                    block->info = policy_info;
                    return block + 1;
                }
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
    allocated += chunk_size;
    available += block_size;
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

static void *alloc_with_extension(size_t sz, enum ngc_policy policy, union extended_info policy_info)
{
    void *result = allocate(sz, policy, policy_info);

    if (result == NULL) {
        size_t available_before_collection = available;

        ngc_collect(true);
        size_t collected = available - available_before_collection;
        if (collected < minimum_chunk_size/16 || collected < sz + header_size) {
            expand_memory(sz);
        }
        result = allocate(sz, policy, policy_info);
        if (result == NULL) {
            expand_memory(sz);
            result = allocate(sz, policy, policy_info);
        }
    }

    return result;
}

void *ngc_alloc(size_t sz, enum ngc_policy policy)
{
    if (ngc_dont_trace <= policy && policy <= ngc_trace_func4) {
        return alloc_with_extension(sz, policy, (union extended_info) { NULL });
    } else {
        fprintf(stderr, "Bad policy passed to ngc_alloc\n");
        abort();
    }
}

void *ngc_alloc_with_tracer(size_t sz, ngc_trace_function tracer)
{
    return alloc_with_extension(sz, ngc_block_tracer, (union extended_info){ tracer });
}

void *ngc_alloc_with_info(size_t sz, struct ngc_policy_info *policy_info)
{
    return alloc_with_extension(sz, ngc_extended_policy, (union extended_info){ .policy_info = policy_info });
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

void ngc_register_trace_function(enum ngc_policy policy, ngc_trace_function tracer) {
    if (ngc_trace_func1 <= policy && policy <= ngc_trace_func4) {
        tracer_functions[policy - ngc_trace_func1] = tracer;
    } else {
        fprintf(stderr, "Bad policy for ngc_register_trace_function\n");
        abort();
    }
}

void ngc_mark(void *block)
{
    if (block == NULL) {
        return;
    }
    struct block_header *header = block;
    --header;
    if (GET_POLICY(header->size) >= ngc_block_tracer) {
        --header;
    }
    if (! IS_MARKED(header->size)) {
        header->size = SET_MARK(header->size);
        switch (GET_POLICY(header->size)) {
            case ngc_dont_trace:
                break;
            case ngc_trace_func1:
            case ngc_trace_func2:
            case ngc_trace_func3:
            case ngc_trace_func4:
            case ngc_block_tracer:
            case ngc_extended_policy:
                header->next = grey_list;
                grey_list = header;
                break;
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
            case ngc_trace_func1:
            case ngc_trace_func2:
            case ngc_trace_func3:
            case ngc_trace_func4:
                if (tracer_functions[GET_POLICY(header->size) - ngc_trace_func1] != NULL) {
                    tracer_functions[GET_POLICY(header->size) - ngc_trace_func1](header + 1);
                }
                break;
            case ngc_block_tracer:
            {
                struct extended_header *eheader = (struct extended_header*)header;
                ngc_trace_function tracer = eheader->info.trace_function;
                if (tracer != NULL) {
                    tracer(eheader + 1);
                }
                break;
            }
            case ngc_extended_policy:
            {
                struct extended_header *eheader = (struct extended_header*)header;
                struct ngc_policy_info *info = eheader->info.policy_info;
                if (info != NULL && info->tracer != NULL) {
                    info->tracer(eheader + 1);
                }
                break;
            }
        }
    }
}

static void mark_all()
{
    for (size_t i = 0; i < num_root_tracers; ++i) {
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
    available = 0;
    free_list = NULL;
    last_free = NULL;
    current_free = NULL;
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        struct block_header *end_chunk = chunk + chunk->size / header_size;
        for (struct block_header *header = chunk + 1;
             header < end_chunk;
             header = header + header->size / header_size)
        {
            if (IS_MARKED(header->size)) {
                header->size = CLEAR_MARK(header->size);
            } else {
                if (GET_POLICY(header->size) == ngc_extended_policy) {
                    struct extended_header *eheader = (struct extended_header*)header;
                    struct ngc_policy_info *info = eheader->info.policy_info;
                    if (info != NULL && info->finalizer != NULL) {
                        info->finalizer(eheader + 1);
                    }
                }
                header->size = CLEAR_ALL(header->size);
                available += header->size;
                header->next = NULL;
                if (last_free == NULL) {
                    free_list = header;
                    last_free = header;
                } else if (header != last_free + last_free->size / header_size){
                    last_free->next = header;
                    last_free = header;
                } else {
                    last_free->size += header->size;
                }
            }
        }
    }
}

void ngc_collect(bool force)
{
    if (force || available_after_last_collect < available + minimum_chunk_size / 16) {
        mark_all();
        sweep_all();
        available_after_last_collect = available;
    }
}

int ngc_consistency_check(FILE* f)
{
    int num_errors = 0;

    // check that all blocks are unmarked and check some sums
    size_t allocated_by_chunks = 0;
    size_t allocated_by_blocks = 0;
    size_t free_by_blocks = 0;
    size_t num_chunks = 0;
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        allocated_by_chunks += chunk->size;
        ++num_chunks;
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            allocated_by_blocks += CLEAR_ALL(block->size);
            if (IS_MARKED(block->size)) {
                fprintf(f, "block at %p is marked\n", (void*) block);
                ++num_errors;
            }
            if (GET_POLICY(block->size) == ngc_free_block) {
                free_by_blocks += CLEAR_ALL(block->size);
            }
        }
    }
    if (allocated_by_chunks != allocated) {
        fprintf(f, "allocated (%zu) != allocated_by_chunks(%zu)\n", allocated, allocated_by_chunks);
        ++num_errors;
    }
    if (allocated_by_blocks + num_chunks * header_size != allocated) {
        fprintf(f, "allocated (%zu) != allocated_by_blocks(%zu)\n", allocated, allocated_by_blocks);
        ++num_errors;
    }
    if (free_by_blocks != available) {
        fprintf(f, "available (%zu) != free_by_blocks(%zu)\n", available, free_by_blocks);
        ++num_errors;
    }

    // check that the free list contains all free blocks
    free_by_blocks = 0;
    for (struct block_header *current = free_list; current != NULL; current = current->next) {
        if (GET_POLICY(current->size) != ngc_free_block) {
            fprintf(f, "block at %p is in free list and not marked as free\n", (void*) current);
        }
        current->size = SET_MARK(current->size);
        free_by_blocks += CLEAR_ALL(current->size);
    }
    if (free_by_blocks != available) {
        fprintf(f, "available (%zu) != size in free list (%zu)\n", available, free_by_blocks);
        ++num_errors;
    }

    // second pass on all the block
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            if (IS_MARKED(block->size)) {
                block->size = CLEAR_MARK(block->size);
            } else if (GET_POLICY(block->size) == ngc_free_block) {
                fprintf(f, "block at %p marked as free but not in free list\n", (void*) block);
                ++num_errors;
            }
            if (GET_POLICY(block->size) != ngc_free_block
                && block->next != NULL)
            {
                fprintf(f, "allocated block at %p has a next pointer\n", (void*) block);
                ++num_errors;
            }
        }
    }

    return num_errors;
}

void ngc_debug_dump(FILE *f)
{
    fprintf(f, "\nNGC Memory map\n\n");
    fprintf(f, "header_size:        %#zx\n", header_size);
    fprintf(f, "minimum_chunk_size: %#zx\n\n", minimum_chunk_size);

    fprintf(f, "available/allocated: %zu/%zu\n\n", available, allocated);

    fprintf(f, "first_chunk:  %18p\n", (void*) first_chunk);
    fprintf(f, "last_chunk:   %18p\n", (void*) last_chunk);
    fprintf(f, "free_list:    %18p\n", (void*) free_list);
    fprintf(f, "prev_free:    %18p\n", (void*) prev_free);
    fprintf(f, "current_free: %18p\n", (void*) current_free);
    fprintf(f, "last_free:    %18p\n\n", (void*) last_free);

    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        fprintf(f, "Chunk at %18p, size: %#8zx, next: %18p\n", (void*) chunk, chunk->size, (void*) chunk->next);
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            fprintf(f, "Block at %18p, size: %#8zx, next: %18p\n", (void*) block, block->size, (void*) block->next);
        }
        fprintf(f, "\n");
    }
}

struct block_header *find_chunk(struct block_header *block, int *chunk_number_ptr)
{
    int result = 0;
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next)
    {
        if (chunk <= block && block < chunk + chunk->size / header_size) {
            if (chunk_number_ptr != NULL) {
                *chunk_number_ptr= result;
            }
            return chunk;
        }
        ++result;
    }
    if (chunk_number_ptr != NULL) {
        *chunk_number_ptr = -1;
    }
    return NULL;
}

void ngc_test_dump(FILE *f)
{
    int display_chunk_number;
    struct block_header *display_chunk;
    fprintf(f, "\nNGC Memory map\n\n");
    fprintf(f, "header_size:        %#zx\n", header_size);
    fprintf(f, "minimum_chunk_size: %#zx\n\n", minimum_chunk_size);

    fprintf(f, "available/allocated: %zu/%zu\n\n", available, allocated);

    display_chunk = find_chunk(free_list, &display_chunk_number);
    fprintf(f, "free_list:    %3d + %18zx\n", display_chunk_number, (char*)free_list - (char*)display_chunk);
    display_chunk = find_chunk(prev_free, &display_chunk_number);
    fprintf(f, "prev_free:    %3d + %18zx\n", display_chunk_number, (char*)prev_free - (char*)display_chunk);
    display_chunk = find_chunk(current_free, &display_chunk_number);
    fprintf(f, "current_free: %3d + %18zx\n", display_chunk_number, (char*)current_free - (char*)display_chunk);
    display_chunk = find_chunk(last_free, &display_chunk_number);
    fprintf(f, "last_free:    %3d + %18zx\n\n", display_chunk_number, (char*)last_free - (char*)display_chunk);

    int chunk_number = 0;
    for (struct block_header *chunk = first_chunk; chunk != NULL; chunk = chunk->next) {
        fprintf(f, "Chunk %3d, size: %#8zx\n", chunk_number, chunk->size);
        ++chunk_number;
        for (struct block_header *block = chunk + 1;
             block < chunk + chunk->size / header_size;
             block = block + block->size / header_size)
        {
            display_chunk = find_chunk(block->next, &display_chunk_number);
            fprintf(f, "Block at %18zx, size: %#8zx, next: %3d + %18zx\n", (char*)block - (char*)chunk, block->size,
                    display_chunk_number, (char*)(block->next) - (char*) display_chunk);
        }
        fprintf(f, "\n");
    }
}

void ngc_debug(FILE* f)
{
    if (getenv("NGC_DEBUG_DUMP") != NULL) {
        ngc_debug_dump(f);
    } else {
        ngc_test_dump(f);
    }
    ngc_consistency_check(f);
}