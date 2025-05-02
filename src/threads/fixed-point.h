#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

/* Fixed point number type with 17.14 format
   (17 bits for integer part, 14 bits for fractional part) */
typedef int32_t fixed_point_t;

/* Number of bits for fractional part */
#define F (1 << 14)

/* Convert integer to fixed point */
#define INT_TO_FP(n) ((fixed_point_t)(n) * F)

/* Convert fixed point to integer (rounding toward zero) */
#define FP_TO_INT(x) ((x) / F)

/* Convert fixed point to integer (rounding to nearest) */
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F/2) / F : ((x) - F/2) / F)

/* Add two fixed-point numbers */
#define ADD_FP(x, y) ((x) + (y))

/* Subtract two fixed-point numbers */
#define SUB_FP(x, y) ((x) - (y))

/* Add fixed-point number and integer */
#define ADD_FP_INT(x, n) ((x) + (n) * F)

/* Subtract integer from fixed-point number */
#define SUB_FP_INT(x, n) ((x) - (n) * F)

/* Multiply two fixed-point numbers */
#define MULT_FP(x, y) ((fixed_point_t)(((int64_t)(x)) * (y) / F))

/* Multiply fixed-point number by integer */
#define MULT_FP_INT(x, n) ((x) * (n))

/* Divide two fixed-point numbers */
#define DIV_FP(x, y) ((fixed_point_t)(((int64_t)(x)) * F / (y)))

/* Divide fixed-point number by integer */
#define DIV_FP_INT(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */