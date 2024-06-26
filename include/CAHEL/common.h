#pragma once

//#include "util/defines.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <tuple>
//#include <type_traits>
#include <utility>
#include <vector>
#include <stdio.h>

#define SWITCH_POINT 2048
#define MAX_THREAD_PER_BLOCK 1024
#define NTT_THREAD_PER_BLOCK 1024

namespace cahel {
    namespace util {
        // MUST dividible by poly_degree
        constexpr dim3 blockDimGlb(128);

        // ntt block threads, max = 2^16 * coeff_mod_size / (8*thread) as we do 8 pre-thread ntt
        constexpr dim3 gridDimNTT(4096);
        constexpr dim3 blockDimNTT(128);

        constexpr double two_pow_64 = 18446744073709551616.0;

        constexpr int sid_count = 8;

        __device__ __constant__ constexpr double two_pow_64_dev = 18446744073709551616.0;

        __device__ __constant__ constexpr int bytes_per_uint64_dev = sizeof(std::uint64_t);

        __device__ __constant__ constexpr int bits_per_nibble_dev = 4;

        __device__ __constant__ constexpr int bits_per_byte_dev = 8;

        __device__ __constant__ constexpr int bits_per_uint64_dev = bytes_per_uint64_dev * bits_per_byte_dev;

        __device__ __constant__ constexpr int nibbles_per_byte_dev = 2;

        __device__ __constant__ constexpr int nibbles_per_uint64_dev = bytes_per_uint64_dev * nibbles_per_byte_dev;

    }
}

// CUDA to check the last error information
inline void cuda_check(cudaError_t status, const char *action = NULL, const char *file = NULL, int32_t line = 0) {
    // check for cuda errors
    if (status != cudaSuccess) {
        printf("CUDA error occurred: %s\n", cudaGetErrorString(status));
        if (action != NULL)
            printf("While running %s   (file %s, line %d)\n", action, file, line);
        // exit(1);
        cudaGetLastError(); //
        throw std::logic_error("CUDA error!");
    }
}

#define CUDA_CHECK(action) cuda_check(action, #action, __FILE__, __LINE__)
