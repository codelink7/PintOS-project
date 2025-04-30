#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H
#include <stdint.h>


/* Fixed point number type with 17.14 format
   (17 bits for integer part, 14 bits for fractional part) */
typedef int32_t fixed_point_t;
#define FP_F (1 << 14) /* 2^14 */ 

/* Convert integer to fixed-point value */
#define INT_TO_FP(n) ((n) * FP_F)
 
/* Convert fixed-point value to integer (rounding toward zero) */
#define FP_TO_INT_ROUND_ZERO(x) ((x) / FP_F)

/* Convert fixed-point value to integer (rounding to nearest) */
#define FP_TO_INT_ROUND_NEAREST(x) ((x) >= 0 ? ((x) + FP_F / 2) / FP_F : ((x) - FP_F / 2) / FP_F)
  
/* Add two fixed-point values */
#define FP_ADD(x, y) ((x) + (y))

/* Subtract fixed-point value y from x */
#define FP_SUB(x, y) ((x) - (y))

/* Add integer n to fixed-point value x */
#define FP_ADD_INT(x, n) ((x) + (n) * FP_F)

/* Subtract integer n from fixed-point value x */
#define FP_SUB_INT(x, n) ((x) - (n) * FP_F)

/* Multiply two fixed-point values */
#define FP_MULT(x, y) (((int64_t)(x)) * (y) / FP_F)

/* Multiply fixed-point value x by integer n */
#define FP_MULT_INT(x, n) ((x) * (n))

/* Divide fixed-point value x by fixed-point value y */
#define FP_DIV(x, y) (((int64_t)(x)) * FP_F / (y))

/* Divide fixed-point value x by integer n */
#define FP_DIV_INT(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */