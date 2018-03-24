#include <iostream>
#include "PartyR.h"
#include "PartyS.h"
#include "zp.h"

int main(int argc, char* argv[]) {

    std::cout << "Run Protocol" << std::endl;

    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);
    int partyNum = stoi(parser.getValueByKey(parameters, "partyID"));


    if (partyNum == 0) {
        // create Party one with the previous created objects.
        PartyR pR(argc, argv);

        auto all = scapi_now();
        pR.runProtocol();
        auto end = std::chrono::system_clock::now();

        long elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        cout << "********************* PartyR ********\nRunning took " << elapsed_ms << " milliseconds" << endl;


        //write the results to file
        pR.writeResultsToFile();

    }
    else if (partyNum == 1) {
        auto all = scapi_now();
        PartyS pS(argc, argv);
        pS.runProtocol();
        auto end = std::chrono::system_clock::now();

        long elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        cout << "********************* PartyS ********\nRunning took " << elapsed_ms << " milliseconds" << endl;
    }


    return 0;




    //ZZ prime(2305843009213693951);
//    ZZ_p::init(ZZ(2305843009213693951));
//
//
//    test_multipoint_eval_zp(ZZ(2305843009213693951), 999999, 8);
////    test_interpolate_zp(ZZ(2305843009213693951), 99999);
//
//
////    vector<ZZ_pX> evalTree; //holds the tree for all slices
////    vector<ZZ_pX> evalRemainder;
////    vector<ZZ_p> inputs;
////    int numOfItems = 8;
////
////    evalTree.resize(numOfItems * 2 - 1);
////    evalRemainder.resize(numOfItems * 2 - 1);
////
////    inputs.resize(numOfItems);
////
////
////
////    for(int i=0; i<numOfItems; i++){
////        inputs[i] = to_ZZ_p(ZZ(i));
////
////    }
////
////
////    steady_clock::time_point begin1 = steady_clock::now();
////
////    build_tree(evalTree.data(), inputs.data(), 2*numOfItems -1);
////    test_tree(evalTree.data()[0], inputs.data(), numOfItems);
////
////    steady_clock::time_point end1 = steady_clock::now();
////    cout << "Building tree - total: " << duration_cast<milliseconds>(end1 - begin1).count() << " ms" << endl;

    
}