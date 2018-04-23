//
// Created by bush on 16/04/18.
//

#include "Poly.h"

#include <cstdlib>
#include <stdio.h>
#include <cassert>
#include <array>
#include <bitset>
#include <chrono>
#include <sys/resource.h>
#include <cinttypes>

#include <byteswap.h>

#define TEST

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




typedef uint64_t u64;
typedef  __m128i block;

void print_bits ( void* buf, size_t size_in_bits, size_t skip_bits=0)
{
    unsigned char* ptr = (unsigned char*)buf;
    size_t ctr = 0;
    size_t ctr_skip = 0;
    while(ctr<size_in_bits) {
        for (short j = 7; j >= 0 && ctr<size_in_bits; j--) {
            if(skip_bits && ctr_skip<skip_bits-1){
                ctr_skip++;
                continue;
            }
            printf("%d", (*ptr >> j) & 1);
            ctr++;
        }
        cout << " ";
        ptr++;
    }
//    printf("\n");
}

void randomPoints(std::vector<std::array<block, 4>>& setX,
                  std::vector<std::array<block, 4>>& setY) {
    srand (time(NULL));
    uint size = setX.size();
    for (uint i=0; i<size; i++) {
        uint *px = (uint*)&(setX[i][0]);
        uint *py = (uint*)&(setY[i][0]);
        for(uint j=0; j<16; j++) {
            *px = rand();
            *py = rand();
            px++;
            py++;
        }
        px--;py--;
        *px &= 0x000000FF;
        *py &= 0x000000FF;
    }
}

bool blocksEqual(array<block, 4>& a, array<block, 4>& b) {
    ulong *pa = (ulong*)&a[0], *pb = (ulong*)&b[0];
    for (uint i=0; i<8; i++)
        if (*pa++ != *pb++)
            return false;
    return true;
}

void initMersenneAfterHash(vector<array<block, 4>>& setX,
                           vector<array<block, 4>>& setY,
                           array<vector<ZpMersenneLongElement>,8>& X,
                           array<vector<ZpMersenneLongElement>,8>& Y) {
    uint size = setX.size();
//    for(uint s=0; s<8; s++) {
//        X[s].resize(size);
//        Y[s].resize(size);
//    }

    unsigned char temp;
    unsigned long tmpx=0, tmpy=0;
    for(uint i=0; i<size; i++) {
        //this is in case we hash each item first before interpolation.
        unsigned char *startx = (unsigned char*)(&setX[i][0]);
        unsigned char *starty = (unsigned char*)(&setY[i][0]);

        tmpx = bswap_64(*(ulong*)startx);
        tmpy = bswap_64(*(ulong*)starty);
        tmpx >>= 3;
        tmpy >>= 3;
        X[0][i].elem = tmpx;
        Y[0][i].elem = tmpy;

        X[1][i].elem = bswap_64(*(ulong*)(startx+7));
        Y[1][i].elem = bswap_64(*(ulong*)(starty+7));
        X[1][i].elem <<= 5;
        Y[1][i].elem <<= 5;
        X[1][i].elem >>= 3;
        Y[1][i].elem >>= 3;
        temp = startx[15]>>6;
        X[1][i].elem += temp;
        temp = starty[15]>>6;
        Y[1][i].elem += temp;

        X[2][i].elem = bswap_64(*(ulong*)(startx+15));
        Y[2][i].elem = bswap_64(*(ulong*)(starty+15));
        X[2][i].elem <<= 2;
        Y[2][i].elem <<= 2;
        X[2][i].elem >>= 3;
        Y[2][i].elem >>= 3;

        X[3][i].elem = bswap_64(*(ulong*)(startx+22));
        Y[3][i].elem = bswap_64(*(ulong*)(starty+22));
        X[3][i].elem <<= 7;
        Y[3][i].elem <<= 7;
        X[3][i].elem >>= 3;
        Y[3][i].elem >>= 3;
        temp = startx[30]>>4;
        X[3][i].elem += temp;
        temp = starty[30]>>4;
        Y[3][i].elem += temp;

        X[4][i].elem = bswap_64(*(ulong*)(startx+30));
        Y[4][i].elem = bswap_64(*(ulong*)(starty+30));
        X[4][i].elem <<= 4;
        Y[4][i].elem <<= 4;
        X[4][i].elem >>= 3;
        Y[4][i].elem >>= 3;
        temp = startx[38]>>7;
        X[4][i].elem += temp;
        temp = starty[38]>>7;
        Y[4][i].elem += temp;

        X[5][i].elem = bswap_64(*(ulong*)(startx+38));
        Y[5][i].elem = bswap_64(*(ulong*)(starty+38));
        X[5][i].elem <<= 1;
        Y[5][i].elem <<= 1;
        X[5][i].elem >>= 3;
        Y[5][i].elem >>= 3;

        X[6][i].elem = bswap_64(*(ulong*)(startx+45));
        Y[6][i].elem = bswap_64(*(ulong*)(starty+45));
        X[6][i].elem <<= 6;
        Y[6][i].elem <<= 6;
        X[6][i].elem >>= 3;
        Y[6][i].elem >>= 3;
        temp = startx[53]>>5;
        X[6][i].elem += temp;
        temp = starty[53]>>5;
        Y[6][i].elem += temp;

        X[7][i].elem = bswap_64(*(ulong*)(startx+53));
        Y[7][i].elem = bswap_64(*(ulong*)(starty+53));
        X[7][i].elem <<= 3;
        Y[7][i].elem <<= 3;
        X[7][i].elem >>= 3;
        Y[7][i].elem >>= 3;
    }

#ifdef TEST
    for (uint i=0; i<size; i++) {
        for (uint s = 0; s < 8; s++) {
            if (X[s][i].elem >= ZpMersenneLongElement::p
                || Y[s][i].elem >= ZpMersenneLongElement::p
                    )
                cout << "bad " << s << endl;
        }
    }
    cout << "all good" << endl;
#endif
}

void getBlkCoefficients(u64 degree,
                        vector<array<block, 4>>& setX,
                        vector<array<block, 4>>& setY,
                        vector<array<block, 4>>& coeffs,
                        array<vector<ZpMersenneLongElement>,8>& X,
                        array<vector<ZpMersenneLongElement>,8>& Y,
                        array<vector<ZpMersenneLongElement>,8>& C
) {
    //assuming 8 slices: 61*8=488
    uint size = setX.size(); //assuming setX.size()=setY.size()=coeffs.size()
//    array<vector<ZpMersenneLongElement>,8> X,Y,C;

    for(uint s=0; s<8; s++) {
        X[s].resize(size);
        Y[s].resize(size);
        C[s].resize(size);
    }
    initMersenneAfterHash(setX,setY,X,Y);

    for(uint s=0; s<8; s++) {
        Poly::interpolateMersenne(C[s], X[s], Y[s]);
    }

    unsigned long *p= nullptr;
    for(uint i=0; i<size; i++) {
        p = (unsigned long*)(&coeffs[i][0]);
        for(uint s=0; s<8; s++) {
            *p = C[s][i].elem;
            p++;
        }
    }
}


void evalSuperPolynomial(vector<array<block, 4>>& coeffs,
                         vector<array<block, 4>>& setX,
                         vector<array<block, 4>>& setY,
                         vector<array<block, 4>>& realSetY,
                         array<vector<ZpMersenneLongElement>,8>& realX,
                         array<vector<ZpMersenneLongElement>,8>& realY,
                         array<vector<ZpMersenneLongElement>,8>& realC
) {
    uint size = setX.size();
    array<vector<ZpMersenneLongElement>,8> X,Y,C;
    for(uint s=0; s<8; s++) {
        X[s].resize(size);
        Y[s].resize(size);
        C[s].resize(size);
    }

    //take coeffs to the mersenne form
    unsigned long *p= nullptr;
    for(uint i=0; i<size; i++) {
        p = (unsigned long*)(&coeffs[i][0]);
        for(uint s=0; s<8; s++) {
            C[s][i].elem = *p;
            p++;
        }
    }

#ifdef TEST
    for (uint i = 0; i < size; i++) {
        for (uint s = 0; s < 8; s++) {
            if (C[s][i].elem != realC[s][i].elem) {
                cout << "C is bad" << endl;
                exit(1);
            }
        }
    }
    cout << "all coefficeints copied correctly!" << endl;
#endif

    //take setX to mersenne form
    unsigned char temp;
    unsigned long tmpx=0;
    for(uint i=0; i<size; i++) {
        //this is in case we hash each item first before interpolation.
        unsigned char *startx = (unsigned char *) (&setX[i][0]);

        tmpx = bswap_64(*(ulong *) startx);
        tmpx >>= 3;
        X[0][i].elem = tmpx;

        X[1][i].elem = bswap_64(*(ulong *) (startx + 7));
        X[1][i].elem <<= 5;
        X[1][i].elem >>= 3;
        temp = startx[15] >> 6;
        X[1][i].elem += temp;

        X[2][i].elem = bswap_64(*(ulong *) (startx + 15));
        X[2][i].elem <<= 2;
        X[2][i].elem >>= 3;

        X[3][i].elem = bswap_64(*(ulong *) (startx + 22));
        X[3][i].elem <<= 7;
        X[3][i].elem >>= 3;
        temp = startx[30] >> 4;
        X[3][i].elem += temp;

        X[4][i].elem = bswap_64(*(ulong *) (startx + 30));
        X[4][i].elem <<= 4;
        X[4][i].elem >>= 3;
        temp = startx[38] >> 7;
        X[4][i].elem += temp;

        X[5][i].elem = bswap_64(*(ulong *) (startx + 38));
        X[5][i].elem <<= 1;
        X[5][i].elem >>= 3;

        X[6][i].elem = bswap_64(*(ulong *) (startx + 45));
        X[6][i].elem <<= 6;
        X[6][i].elem >>= 3;
        temp = startx[53] >> 5;
        X[6][i].elem += temp;

        X[7][i].elem = bswap_64(*(ulong *) (startx + 53));
        X[7][i].elem <<= 3;
        X[7][i].elem >>= 3;

    }

#ifdef TEST
    for (uint i = 0; i < size; i++) {
        for (uint s = 0; s < 8; s++) {
            if (X[s][i].elem != realX[s][i].elem) {
                cout << "X is bad" << endl;
                exit(1);
            }
        }
    }
    cout << "all Xs copied correctly!" << endl;
#endif

    //evaluate all Xs for all slices to obtain Y
    for (uint s=0; s<8; s++) {
        for (uint i = 0; i < size; i++) {
            Poly::evalMersenne(Y[s][i], C[s], X[s][i]);
        }
    }
#ifdef TEST
    for (uint i = 0; i < size; i++) {
        for (uint s = 0; s < 8; s++) {
            if (Y[s][i].elem != realY[s][i].elem) {
                cout << "Y is bad" << endl;
                exit(1);
            }
        }
    }
    cout << "all Ys evaluated correctly!" << endl;
#endif

    //take Y's back to blocks form
    ulong t;
    for (uint i=0; i<size; i++) {
        ulong *startrealy = (ulong *) (&realSetY[i][0]);
        ulong *starty = (ulong *) (&setY[i][0]);

        *starty = Y[0][i].elem;
        *starty <<= 3;
        t = Y[1][i].elem>>58;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[1][i].elem;
        *starty <<= 6;
        t = Y[2][i].elem>>55;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[2][i].elem;
        *starty <<= 9;
        t = Y[3][i].elem>>52;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[3][i].elem;
        *starty <<= 12;
        t = Y[4][i].elem>>49;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[4][i].elem;
        *starty <<= 15;
        t = Y[5][i].elem>>46;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[5][i].elem;
        *starty <<= 18;
        t = Y[6][i].elem>>43;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[6][i].elem;
        *starty <<= 21;
        t = Y[7][i].elem>>40;
        *starty += t;
        *starty = bswap_64(*starty);
        starty++;

        *starty = Y[7][i].elem;
        *starty <<= 24;
//        t = Y[8][i].elem>>37;
//        *starty += t;
        *starty = bswap_64(*starty);
        starty++;
    }

#ifdef TEST
    for (uint i=0; i<size; i++) {
        if (!blocksEqual(setY[i], realSetY[i])) {
            cout << "blocks not equal! after evaluation" << endl;
            exit(1);
        }
    }
    cout << "all blocks equal, evaluation succeeded!" << endl;
#endif

}




void test_with_blocks();
int main () {

    uint binsize = 40;
    std::vector<std::array<block, 4>> setX(binsize), setY(binsize), coeffs(binsize);
    array<vector<ZpMersenneLongElement>,8> X,Y,C;
    randomPoints(setX,setY);
    getBlkCoefficients(binsize-1, setX,setY,coeffs, X,Y,C);

    std::vector<std::array<block, 4>> newY(binsize);
    evalSuperPolynomial(coeffs, setX, newY, setY, X,Y,C);

//    test_with_blocks();
}



void test_with_blocks() {
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