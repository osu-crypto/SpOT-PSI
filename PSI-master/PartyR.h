//
// Created by meital on 10/01/18.
//

#ifndef PSI_PARTYR_H
#define PSI_PARTYR_H

#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"
#include "../../include/primitives/Mersenne.hpp"
#include "../../include/primitives/PrfOpenSSL.hpp"
#include "Party.h"

#include "NTL/ZZ_p.h"
#include "NTL/ZZ_pX.h"



/**
 * This class is the Reciever party in the protocol based on the paper "Minimalist Private Set Intersection
 * via Sparse OT Extension", a lightweight technique for two-party private set intersection (PSI) with semi-honest security.
 *
 * The protocol for both parties is as follows (taken from the paper)
 *
 *
 *
 * ------------This class implements party S (Alice) -----------------
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
 */
class PartyR : public Party {


private:

    vector<byte> T;//the first array for the input of the ot's
    vector<byte> U;//the second array for the input of the ot's
    vector<vector<byte>>tRows;
    vector<vector<vector<byte>>>tSplitRows;//TODO use better data structures to keep data sequential
    vector<vector<byte>>uRows;//TODO use better data structures to keep data sequential
    vector<vector<byte>>zRows;//TODO use better data structures to keep data sequential

    vector<vector<byte>> tSha;

    vector<vector<byte>>tbitArr;
    vector<vector<byte>>ubitArr;


    vector<ZZ_pX> interpolateTree;//for interpolation
    vector<ZZ_p> interpolatePoints;
    vector<ZZ_pX> interpolateTemp;



    OTBatchSender * otSender;			//The OT object that used in the protocol.

    int amount=0;//amout of items matched




public:
    PartyR(int atgc, char* argv[]);//int numOfItems, int groupNum, string myIp = "127.0.0.1",  string otherIp = "127.0.0.1", int myPort = 1213,int otherPort = 1212);

    ~PartyR(){
        io_service.stop();
        delete timer;
    }



    /**
     * Runs the protocol of the reciever side, both the online and the offline.
     *
     * 1. runOT();
     * 2. prepareInterpolateValues();
     * 3. for(int i=0; i<NUM_OF_SPLITS; i++) {
     *      buildPolinomial(i);
     *      sendCoeffs();
     *    }
     * 4. recieveHashValues();
     * 5. calcOutput();
     */
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

    void writeResultsToFile();

private:

    /**
     * gets the items to be checked for intersection
     */
    void getInput();

    /**
     * Runs a random OT as the sender. The number of ot's is SIZE_OF_NEEDED_BITS which is the size of the
     * underlying total field size.
     * The output of the OT is then put in T and U.
     */
    void runOT();

    /**
     * This methods invokes the common functionality of all interpolation slices (splits).
     * The function does the following:
     * 1. Build tree:
     * 2. Differentiate
     * 3. Evaluate diff
     *
     * To complete interpolation a call to the function iterative_interpolate_zp should be placed.
     */
    void prepareInterpolateValues();

    /**
     * 1. For inputes y , computes R(y) = T(y) ⊕ U(y), where:
     *      T(y) := AES(t1, y)|AES(t2, y)| · · · |AES(t`, y)
     *      U(y) := AES(u1, y)|AES(u2, y)| · · · |AES(u`, y)
     *    This is done only for the current slice "split", thus only the size of the split columns are encrypted.
     *
     * 2. compute a polynomial P := InterpF ({y, R(y)}y∈Y ).
     *    Call only the iterative_interpolate_zp for split only, no need to invoke
     *    the common parts of prepareInterpolateValues().
     *
     * Note that both parts are computed using threads.
     *
     * @param split - the slice index
     */
    void buildPolinomial(int split);

    /**
     * send the interpolated polinomial to S
     */
    void sendCoeffs();

    /**
     * 1. calc my own hash values
     * 2. recieve from S {H(Q(x) ⊕ s · P(x)) | x ∈ X}
     */
    void recieveHashValues();

    /**
     * calculate the intersection by comparing the hash values.
     */
    void calcOutput();

    /**
     *
     * This method is called by a thread.
     * A single bit out of each 128 bit ciphertext is taken.
     * These bits are rearranged into rows.
     *
     * @param start the starting index
     * @param end the ending index
     * @param split the slice index
     */
    void extractBitsThread(int start, int end, int split);

    /**
     * This method is called by a thread.
     * Encrypt the inputs using the keys extracted from the OT. The PRF is aes via AES NI.
     *
     *
     * @param start the starting index
     * @param end the ending index
     * @param split the slice index
     * @param partialInputsAsBytesArr inputs to encrypt, it does not have to be all the inputs, rather just partial inputs.
     */
    void prfEncryptThread(int start, int end, int split, vector<byte> &partialInputsAsBytesArr);

    void setInputsToByteVector(int offset, int numOfItemsToConvert,vector<byte> & inputsAsBytesArr);

    void calcHashValues();

};


#endif //PSI_PARTYR_H
