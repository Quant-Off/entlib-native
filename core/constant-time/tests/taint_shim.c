#include <valgrind/memcheck.h>
#include <stddef.h>

size_t ext_valgrind_make_mem_undefined(const void* addr, size_t len) {
    return VALGRIND_MAKE_MEM_UNDEFINED(addr, len);
}

size_t ext_valgrind_make_mem_defined(const void* addr, size_t len) {
    return VALGRIND_MAKE_MEM_DEFINED(addr, len);
}