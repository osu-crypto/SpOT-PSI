//
// Created by meital on 10/01/18.
//

#ifndef PSI_PARTYS_H
#define PSI_PARTYS_H

#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"
#include "../../include/primitives/Mersenne.hpp"
#include "../../include/primitives/PrfOpenSSL.hpp"
#include "Party.h"
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>


/**
 * This class is the Sender party in the protocol based on the paper "Minimalist Private Set Intersection
 * via Sparse OT Extension", a lightweight technique for two-party private set intersection (PSI) with semi-honest security.
 *
 * The protocol for both parties is as follows (taken from the paper)
 *
 *
 *
 * ------------This class implements party R (Bob) -----------------
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
 */
class PartyS : public Party{

//    boost::asio::io_service io_service;
//    shared_ptr<CommParty> channel;				//The channel between both parties.
    //TemplateField<ZpMersenneLongElement> *field;

//    vector<ZZ_p> inputs;//the elements to check the intersection
//    int numOfItems;//the size of the set

    vector<byte> s;//the random bits for the ot's
    vector<byte> sElements;
    vector<byte> Q;//the results for the ot's
    vector<vector<byte>>qbitArr;
    vector<vector<vector<byte>>>qRows;//TODO use better data structures to keep data sequential
    vector<vector<vector<byte>>>zRows;//TODO use better data structures to keep data sequential

//    OpenSSLSHA256 hash;

//    vector<OpenSSLAES> aesArr;
//    vector<byte> zSha;

//    ZZ_pX polyP;//the polinomial from the interpolation


    vector<ZZ_pX> evalTree; //holds the tree for all slices
    vector<ZZ_pX> evalRemainder;


    OTBatchReceiver * otReceiver;			//The OT object that used in the protocol.

//    vector<ZZ_p> yArr;

public:
    PartyS(int argc, char* argv[]);//int numOfItems, int groupNum, string myIp = "127.0.0.1",  string otherIp = "127.0.0.1", int myPort = 1212,int otherPort = 1213);

    ~PartyS(){
        io_service.stop();
        delete timer;
    }

    void runProtocol();

    /**
    * Runs the protocol.
    */
    void run() override {
        for (currentIteration = 0; currentIteration<times; currentIteration++){
            runOffline();
            runOnline();
        }
    }

    void runOnline() override;
    void runOffline() override;

private:

    void chooseS(int size);

    void runOT();

    void prepareEvalValues();


    void recieveCoeffs(int split);

    void evalAndSet(int split);

    void sendHashValues();

    void setAllKeys();
    void setInputsToByteVector(int offset, int numOfItemsToConvert,vector<byte> & inputsAsBytesArr);


    void getInput();


    void prepareQ();
};


#endif //PSI_PARTYS_H
