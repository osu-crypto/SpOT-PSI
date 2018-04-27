//
// Created by bush on 16/04/18.
//

#include "Poly.h"

#include <cstdlib>
#include <bitset>
#include <chrono>
#include <sys/resource.h>
using namespace chrono;

const unsigned long p61 = 2305843009213693952;

void rand61(ZpMersenneLongElement& e) {

    unsigned long r = rand();
    r <<= 32;
    r+=rand();
    e = r % p61;
}

ZpMersenneLongElement rand61() {
    ZpMersenneLongElement e;
    rand61(e);
    return e;
}

#define CEILING(x,y) (((x) + (y) - 1) / (y))
#define FIELD_SZ (488)
#define NUM_SLICES (CEILING(FIELD_SZ,61))
#define SET_SIZE (1048576) //2^20
#define BIN_SIZE (64) //2^6

union item_t{
    unsigned long e[NUM_SLICES];
} ;


int Mersenne_Test_Impl() {

    system_clock::time_point begin, end;

    begin = system_clock::now();
    vector<item_t> x(SET_SIZE), y(SET_SIZE), coef(SET_SIZE);
    for (int i=0; i<SET_SIZE; i++) {
        for(int s=0; s<NUM_SLICES; s++) {
            x[i].e[s]=rand61().elem;
            y[i].e[s]=rand61().elem;
        }
    }
    end = system_clock::now();
    cout << "init random items: " << duration_cast<milliseconds>(end - begin).count() << " ms" << endl;


    cout << "start interpolate" << endl;
    begin = system_clock::now();

    vector<ZpMersenneLongElement> X(BIN_SIZE),Y(BIN_SIZE), C(BIN_SIZE);
    for(int i=0; i<SET_SIZE; i+=BIN_SIZE) {
        for (int s=0; s<NUM_SLICES; s++) {

            for (int j = 0; j < BIN_SIZE; j++) {
                X[j] = x[i + j].e[s];
                Y[j] = y[i + j].e[s];
            }
            Poly::interpolateMersenne(C, X, Y);

            for (int j = 0; j < BIN_SIZE; j++) {
                coef[i+j].e[s] = C[j].elem;
            }
        }
    }
    end = system_clock::now();
    cout << "interpolate: " << duration_cast<milliseconds>(end - begin).count() << " ms" << endl;

    cout << "start evalutate" << endl;
    begin = system_clock::now();
    for(int i=0; i<SET_SIZE; i+=BIN_SIZE) {
        for (int s = 0; s < NUM_SLICES; s++) {
            for (int j = 0; j < BIN_SIZE; j++) {
                C[j] = coef[i+j].e[s];
                X[j] = x[i+j].e[s];
            }
            for (int j = 0; j < BIN_SIZE; j++) {
                Poly::evalMersenne(Y[j], C, X[j]);
                //need to copy Y[j]
//                ZpMersenneLongElement real_res(y[i+j].e[s]);
//                if(Y[j]!=real_res) {
//                    cout << "result is not good!" << endl;
//                } else {
//                    cout << "result is good!" << endl;
//                }
            }
        }
    }

    end = system_clock::now();
    cout << "evaluate: " << duration_cast<milliseconds>(end - begin).count() << " ms" << endl;
}





void simple_test() {
    unsigned int numbins = pow(2,14);

    vector<ZpMersenneLongElement> coef[numbins];
    for (unsigned int j=0; j<numbins; j++) {
        for (int i = 0; i < 64; i++) {
            coef[j].push_back(rand61());
        }
    }


    vector<ZpMersenneLongElement> x[numbins],y[numbins];
    for (unsigned int j=0; j<numbins; j++) {
        y[j].resize(64);
        for (int i = 0; i < 64; i++) {
            x[j].push_back(rand61());
        }
    }

    Poly poly;
    for (unsigned int j=0; j<numbins; j++) {
        for (int i = 0; i < 64; i++) {
            poly.evalMersenne(y[j][i], coef[j], x[j][i]);
        }
    }

    vector<ZpMersenneLongElement> coef2[numbins];
    system_clock::time_point begin, end;
    begin = system_clock::now();
    for (unsigned int j=0; j<numbins; j++) {
        poly.interpolateMersenne(coef2[j], x[j], y[j]);
    }
    end = system_clock::now();
    cout << "interpolate: " << duration_cast<milliseconds>(end - begin).count() << " ms" << endl;

    bool same = true;
    for (unsigned int j=0; j<numbins; j++) {
        for (int i = 0; i < 64; i++) {
            if (coef2[j][i] != coef[j][i]) {
                same = false;
                break;
            }
        }
    }
    if(same) cout << "coefs are same" << endl;
    else cout << "coefs are different" << endl;
}