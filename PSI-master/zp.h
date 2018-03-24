//
// Created by bush on 29/01/18.
//

#ifndef MPEVAL_ZP_H
#define MPEVAL_ZP_H

#include <chrono>
#include <sys/resource.h>
#include <iostream>

#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <vector>

using namespace std;
using namespace NTL;
using namespace chrono;



void test_multipoint_eval_zp(ZZ prime, long degree,int numThreads);
void test_interpolate_zp(ZZ prime, long degree,int numThreads);

void multipoint_evaluate_zp(ZZ_pX& P, ZZ_p* x, ZZ_p* y, long degree,int numThreads, ZZ &prime);
void interpolate_zp(ZZ_pX& resultP, ZZ_p* x, ZZ_p* y, long degree,int numThreads, ZZ &prime);

void build_tree (ZZ_pX* tree, ZZ_p* points, unsigned int tree_size, int numThreads, ZZ &prime);
void prepareForInterpolate(ZZ_p *x, long degree, ZZ_pX *M, ZZ_p *a, int numThreads, ZZ &prime);
void iterative_interpolate_zp(ZZ_pX& resultP, ZZ_pX* temp, ZZ_p* y, ZZ_p* a, ZZ_pX* M, unsigned int tree_size, int numThreads, ZZ &prime);
void evaluate(ZZ_pX& P, ZZ_pX* tree, ZZ_pX* reminders , unsigned int tree_size, ZZ_p* results, int numThreads, ZZ &prime);
void test_tree (ZZ_pX& final_polynomial, ZZ_p* points, unsigned int npoints);


//helper functions for threads
void generateSubTreeArrays (vector<vector<int>> &subArrays, int totalNodes, int firstIndex);
void buildSubTree (ZZ_pX* tree, vector<int> &subTree, ZZ &prime);
void interSubTree (ZZ_pX* temp, ZZ_pX* M,  vector<int> &subTree, ZZ &prime);
void evalSubTree (ZZ_pX* reminders, ZZ_pX* tree,  vector<int> &subTree, ZZ &prime);
void evalReminder(ZZ_pX *tree, ZZ_pX *reminders, int i, ZZ &prime);
void interSpecific(ZZ_pX *temp, ZZ_pX *M, int i, ZZ &prime);
void buildTreeSpecific(ZZ_pX *tree, int i, ZZ &prime);


void BytesToZZ_px(unsigned char *bytesArr, ZZ_pX& poly, long numOfElements, long sizeOfElement);
void ZZ_pxToBytes(ZZ_pX& poly, unsigned char *bytesArr, long numOfElements, long sizeOfElement);


#endif //MPEVAL_ZP_H
