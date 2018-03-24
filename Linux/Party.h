//
// Created by moriya on 04/02/18.
//

#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/infra/ConfigFile.hpp>
#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/primitives/PrfOpenSSL.hpp>
#include <libscapi/include/infra/Measurement.hpp>

#include <boost/thread/thread.hpp>

#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_p.h>

#ifndef PSI_PARTY_H
#define PSI_PARTY_H

using namespace NTL;

/**
 * This class is the base class of a party in the protocol based on the paper "Minimalist Private Set Intersection
 * via Sparse OT Extension", a lightweight technique for two-party private set intersection (PSI) with semi-honest security.
 *
 * The protocol for both parties is as follows (taken from the paper)
 *
 * Input of Party S (Alice): n items X = {x1, . . . , xn} ⊂ [N]
 * Input of Party R (Bob): n items Y = {y1, . . . , yn} ⊂ [N]
 * Parameters:
 * - Field (NTL ZP),
 * - Hash (sha256 using only 40+2*log(numOfItems) bits
 * - PRF F (aes using openssl aes ni)
 *
 * Protocol:
 * 1. Alice chooses s ← {0, 1} uniformly at random.
 *
 * 2. Alice and Bob invoke fieldSize instances of Random OT such that
 * – Alice acts as receiver with input s
 * – Bob acts as sender, and receives output T,U
 * – Alice receives output Q
 *
 * 3. For y ∈ Y , Bob computes R(y) = T(y) ⊕ U(y), where:
 * T(y) := F(t1, y)|F(t2, y)| · · · |F(t`, y)
 * U(y) := F(u1, y)|F(u2, y)| · · · |F(u`, y)
 *
 * 4. Bob computes a polynomial P := InterpF ({y, R(y)}y∈Y ), and sends its coefficients to Alice
 *
 * 5. Alice defines Q as follows:
 * Q(x) := F(q1, x)|F(q2, x)| · · · |F(ql, x)
 * and sends O = {H(Q(x) ⊕ s · P(x)) | x ∈ X} randomly permuted to Bob
 *
 * 6. Bob outputs {y ∈ Y | H(T(y)) ∈ O}
 *
 *
 * Slicing - splitting
 * --------------------
 *
 * Having one party (the interpolating party) interpolating the huge-degree polynomial leads to a long idle
 * time by the evaluating party, indicating a serious computational bottleneck. The
 * purpose of our slicing technique is to mollify this by producing several “slices”
 * of the polynomial, such that the computational task of producing a single slice
 * is lighter. This way, once a slice is ready it can immediately be communicated
 * to the evaluating party for evaluation. Moreover, some parts of the interpolation/evaluation can be done
 * only once for a smaller field and then only the rest is done for each slice, reducing the overall work.
 * the slicing technique significantly reduces the idle time of the evaluating party to the time of processing only a
 * single small slice with the interpolation preparations.
 *
 *
 */
class Party : public Protocol{
protected:

    boost::asio::io_service io_service;
    shared_ptr<CommParty> channel;				//The channel between both parties.

    Measurement *timer;
    int times;  //Number of times to execute the protocol
    int currentIteration = 0; //Current iteration number


    vector<ZZ_p> inputs;//the elements to check the intersection
    int numOfItems;//the size of the set


    OpenSSLSHA256 hash;
    int neededHashSize;//the minimum required size of the hash with the required security paramter

    vector<OpenSSLAES> aesArr;
    vector<byte> zSha;

    vector<ZZ_p> yArr;

    ZZ_pX polyP;//the elements to check the intersection

    ZZ prime;

    int numOfThreads;//the maximum num of threads allowed


    int NUM_OF_SPLITS;  //break the computation so at each round we only do SPLIT_FIELD_SIZE bits. This way
                        //the interpolation is broken into parts and there will be much less idle time on both sides.
                        //interpolation running time of R can be used to eval the current polynomial and do some other
                        //required computations in S
    int SPLIT_FIELD_SIZE_BITS;
    int SIZE_SPLIT_FIELD_BYTES;
    int SIZE_OF_NEEDED_BITS;
    int SIZE_OF_NEEDED_BYTES; //we need an extra bit for the field and thus  (SIZE_OF_NEEDED_BITS + 7/8) is not good enough

public:
    Party(int argc, char* argv[]);
    ~Party();

    bool hasOffline() override { return true; }
    bool hasOnline() override { return true; }
};


#endif //PSI_PARTY_H
