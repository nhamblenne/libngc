![CMake](https://github.com/nhamblenne/libngc/actions/workflows/CMake.yml/badge.svg)

# NIH Garbage Collector

Here is a simple mark and sweep garbage collector written in C.

If you want something more tried, see the [Boehm-Demers-Weiser conservative
garbadge collector](https://www.hboehm.info/gc), this project is mainly for
my own education.  Although I intend to use it in some personal projects,
and to fix its bugs affecting those projects, I won't probably do any
enhancement above what I need.

It is a precise garbage collector, thus you have to be able to determine
where are the pointers to the memory handled by libngc in your memory
block.

## Usage

See `ngc.h` for details.

Use `ngc_register_root_tracer` to register functions able to list your
roots.

Use `ngc_set_root` and `ngc_unset_root` to temporarily marks your
root. Long term roots are better handler by a root tracer.

Use `ngc_trace_function` to register a function able to marks the pointers
contained in an allocated memory block.

Use `ngc_mark` to mark as live allocated memory in trace functions.

Use `ngc_collect` to force a collection cycle.

## Contributing

Bugs reports and fixes are welcome.

Before doing any enhancement, please discuss them with me as I'll probably
not accept merge requests if they don't correspond to my plan for this
project. The issue list contains enhancements I either intend to do or at
least consider in scope, but that list is probably not exhaustive and I may
accept things which are not there.
