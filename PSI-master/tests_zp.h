//
// Created by bush on 13/01/18.
//

#ifndef MPEVAL_TESTS_ZP_H
#define MPEVAL_TESTS_ZP_H

#include <chrono>
#include <sys/resource.h>
#include "utils_zp.h"

using namespace std;
using namespace chrono;
using namespace NTL;

//void multipoint_evaluate_zp(ZZ_pX& P, ZZ_p* x, ZZ_p* y, long degree);
void test_multipoint_eval_zp(ZZ prime, long degree);

//void interpolate_zp(ZZ_pX& resultP, ZZ_p* x, ZZ_p* y, long degree);
void test_interpolate_zp(ZZ prime, long degree);
void test_interpolation_result_zp(ZZ_pX& P, ZZ_p* x, ZZ_p* y, long degree);

#endif //MPEVAL_TESTS_ZP_H
