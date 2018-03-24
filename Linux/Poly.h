//
// Created by meital on 14/01/18.
//

#ifndef PSI_POLY_H
#define PSI_POLY_H


#include "../../include/primitives/Mersenne.hpp"

class Poly {

public:

    static void evalMersenne(ZpMersenneLongElement &b, const vector<ZpMersenneLongElement>& coeff, ZpMersenneLongElement a);
    static void interpolateMersenne(vector<ZpMersenneLongElement>& coeff, const vector<ZpMersenneLongElement>& a, vector<ZpMersenneLongElement>& b);

};


#endif //PSI_POLY_H
