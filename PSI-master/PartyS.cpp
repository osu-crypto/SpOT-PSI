//
// Created by meital on 10/01/18.
//

#include "PartyS.h"

#include <boost/thread/thread.hpp>
#include "../../include/comm/Comm.hpp"
#include "Defines.h"
#include "Poly.h"
#include "tests_zp.h"
#include "zp.h"
#include "NTL/ZZ.h"
#include <omp.h>

PartyS::PartyS(int argc, char* argv[] ) : Party(argc, argv){



    auto start = scapi_now();
    auto groupNum = stoi(this->getParser().getValueByKey(arguments, "groupID"));

    //open parties file
    string partiesFilePath = this->getParser().getValueByKey(arguments, "partiesFile");
    ConfigFile cf(partiesFilePath);

    string receiver_ip, sender_ip;
    int receiver_port, sender_port;

    //get partys IPs and ports data
    sender_port = stoi(cf.Value("", "party_0_port"));
    sender_ip = cf.Value("", "party_0_ip");
    receiver_port = stoi(cf.Value("", "party_1_port"));
    receiver_ip = cf.Value("", "party_1_ip");

    SocketPartyData me(IpAddress::from_string(receiver_ip), receiver_port+100*groupNum);

    SocketPartyData other(IpAddress::from_string(sender_ip), sender_port+100*groupNum);
    channel = make_shared<CommPartyTCPSynced>(io_service, me, other);

    sender_port++;

    // create the OT receiver.
    SocketPartyData senderParty(IpAddress::from_string(sender_ip), sender_port + 100*groupNum);
    otReceiver = new OTExtensionBristolReceiver(senderParty.getIpAddress().to_string(), senderParty.getPort(), true, channel);

    // connect to party one
    channel->join(500, 5000);

    vector<string> subTaskNames{"Offline", "ChooseS", "RunOT", "Online", "PrepareQ", "PrepareEvalValues"};
    for (int i=0; i<NUM_OF_SPLITS; i++){
        subTaskNames.push_back("ReceiveCoeffs");
        subTaskNames.push_back("EvalAndSet");
    }
    subTaskNames.push_back("SendHashValues");
    timer = new Measurement(*this, subTaskNames);


    //use
    byte primeBytes[SIZE_SPLIT_FIELD_BYTES];
    channel->read(primeBytes, SIZE_SPLIT_FIELD_BYTES);


    ZZFromBytes(prime, primeBytes, SIZE_SPLIT_FIELD_BYTES);


    ZZ_p::init(ZZ(prime));




    if(FLAG_PRINT)
        cout<<"prime" << prime;



    //field = new TemplateField<ZpMersenneLongElement>(0);
    qRows.resize(NUM_OF_SPLITS);
    zRows.resize(NUM_OF_SPLITS);

    for(int s=0; s<NUM_OF_SPLITS;s++) {

        qRows[s].resize(numOfItems);
        zRows[s].resize(numOfItems);
        for (int i = 0; i < numOfItems; i++) {
            qRows[s][i].resize(SIZE_OF_NEEDED_BYTES);
            zRows[s][i].resize(SIZE_OF_NEEDED_BYTES);

        }

    }

    //this vector is fill by neededHashSize for each item, however the last iteration has hash.getHashedMsgSize() bytes.
    zSha.resize((numOfItems-1)*neededHashSize + hash.getHashedMsgSize());

    yArr.resize(numOfItems);

    qbitArr.resize(SIZE_OF_NEEDED_BITS);
    for(int i=0; i<SIZE_OF_NEEDED_BITS; i++){
        qbitArr[i].resize(16*numOfItems);

    }

    sElements.resize(SIZE_OF_NEEDED_BYTES);
    evalTree.resize(numOfItems * 2 - 1);
    evalRemainder.resize(numOfItems * 2 - 1);
    getInput();
}

void PartyS::getInput()  {

    //----------GET FROM FILE
    inputs.resize(numOfItems);

    for(int i=0; i<numOfItems; i++){
        inputs[i] = to_ZZ_p(ZZ(i));

    }
}

void PartyS::runProtocol(){


    auto all = scapi_now();
    timer->startSubTask("Offline", currentIteration);
    timer->startSubTask("ChooseS", currentIteration);
    chooseS(SIZE_OF_NEEDED_BITS);//this can be done in preprocessing
    timer->endSubTask("ChooseS", currentIteration);
    auto end = std::chrono::system_clock::now();
    int elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - chooseS took " << elapsed_ms << " microseconds" << endl;

    all = scapi_now();
    timer->startSubTask("RunOT", currentIteration);
    runOT();//this can be done in preprocessing
    timer->endSubTask("RunOT", currentIteration);
    timer->endSubTask("Offline", currentIteration); //end of offline
    end = std::chrono::system_clock::now();
    elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - runOT took " << elapsed_ms << " microseconds" << endl;

    timer->startSubTask("Online", currentIteration);
    timer->startSubTask("PrepareQ", currentIteration);
    prepareQ();
    timer->endSubTask("PrepareQ", currentIteration);
    timer->startSubTask("PrepareEvalValues", currentIteration);
    prepareEvalValues();
    timer->endSubTask("PrepareEvalValues", currentIteration);

    for(int i=0; i<NUM_OF_SPLITS; i++) {
        all = scapi_now();
//        timer->startSubTask(6 + i*2, currentIteration);
        recieveCoeffs(i);
//        timer->endSubTask(6 + i*2, currentIteration);
        end = std::chrono::system_clock::now();
        elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        if(FLAG_PRINT_TIMINGS)
            cout << "PartyS - recieveCoeffs took " << elapsed_ms << " milliseconds" << endl;

        all = scapi_now();
//        timer->startSubTask(7 + i*2, currentIteration);
        evalAndSet(i);
//        timer->endSubTask(7 + i*2, currentIteration);
        end = std::chrono::system_clock::now();
        elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        if(FLAG_PRINT_TIMINGS)
            cout << "PartyS - evalAndSet took " << elapsed_ms << " milliseconds" << endl;
        all = scapi_now();
    }
//    timer->startSubTask(6 + NUM_OF_SPLITS*2, currentIteration);
    sendHashValues();
//    timer->endSubTask(6 + NUM_OF_SPLITS*2, currentIteration);
//    timer->endSubTask("Online", currentIteration); //end of online
    end = std::chrono::system_clock::now();
    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - sendHashValues took " << elapsed_ms << " milliseconds" << endl;


}

void PartyS::runOnline() {
    std::chrono::time_point<std::chrono::system_clock> all, end;
    int elapsed_ms;
    timer->startSubTask("Online", currentIteration);
    timer->startSubTask("PrepareQ", currentIteration);
    prepareQ();
    timer->endSubTask("PrepareQ", currentIteration);
    timer->startSubTask("PrepareEvalValues", currentIteration);
    prepareEvalValues();
    timer->endSubTask("PrepareEvalValues", currentIteration);

    for(int i=0; i<NUM_OF_SPLITS; i++) {
        all = scapi_now();
//        timer->startSubTask(6 + i*2, currentIteration);
        recieveCoeffs(i);
//        timer->endSubTask(6 + i*2, currentIteration);
        end = std::chrono::system_clock::now();
        elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        if(FLAG_PRINT_TIMINGS)
            cout << "PartyS - recieveCoeffs took " << elapsed_ms << " milliseconds" << endl;

        all = scapi_now();
//        timer->startSubTask(7 + i*2, currentIteration);
        evalAndSet(i);
//        timer->endSubTask(7 + i*2, currentIteration);
        end = std::chrono::system_clock::now();
        elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
        if(FLAG_PRINT_TIMINGS)
            cout << "PartyS - evalAndSet took " << elapsed_ms << " milliseconds" << endl;
        all = scapi_now();
    }
//    timer->startSubTask(6 + NUM_OF_SPLITS*2, currentIteration);
    sendHashValues();
//    timer->endSubTask(6 + NUM_OF_SPLITS*2, currentIteration);
    timer->endSubTask("Online", currentIteration); //end of online
    end = std::chrono::system_clock::now();
    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - sendHashValues took " << elapsed_ms << " milliseconds" << endl;

}

void PartyS::runOffline() {
    auto all = scapi_now();
    timer->startSubTask("Offline", currentIteration);
    timer->startSubTask("ChooseS", currentIteration);
    chooseS(SIZE_OF_NEEDED_BITS);//this can be done in preprocessing
    timer->endSubTask("ChooseS", currentIteration);
    auto end = std::chrono::system_clock::now();
    int elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - chooseS took " << elapsed_ms << " microseconds" << endl;

    all = scapi_now();
    timer->startSubTask("RunOT", currentIteration);
    runOT();//this can be done in preprocessing
    timer->endSubTask("RunOT", currentIteration);
    timer->endSubTask("Offline", currentIteration); //end of offline
    end = std::chrono::system_clock::now();
    elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - all).count();

    if(FLAG_PRINT_TIMINGS)
        cout << "PartyS - runOT took " << elapsed_ms << " microseconds" << endl;

}


void PartyS::chooseS(int size){

    s.resize(SIZE_OF_NEEDED_BITS);//each bit is represened by byte

    byte * buf = new byte[SIZE_OF_NEEDED_BYTES];
    if (!RAND_bytes(buf, SIZE_OF_NEEDED_BYTES)){

        cout<<"failed to create"<<endl;
    }


//    for(int i=0;i<s.size(); i++)
//        s[i] = 0;
    //go over all the random bytes and set each random bit to a byte containing 0 or 1 for the OT

    sElements[0] = 0;

    int index=0;

    for(int split = 0; split<NUM_OF_SPLITS; split++) {


        for (int i = 0; i < SIZE_SPLIT_FIELD_BYTES; i++) {

            for (int j = 0; j < 8; j++) {

                //get the relevant bit from the random byte
                if (i * 8 + j < SPLIT_FIELD_SIZE_BITS) {
                    s[index] = (buf[(split * SIZE_SPLIT_FIELD_BYTES) + i] >> j) & 1;
                    index++;
                }


            }
            ((byte *) sElements.data())[split*SIZE_SPLIT_FIELD_BYTES + i] = buf[(split*SIZE_SPLIT_FIELD_BYTES)+i];
        }
    }

}

void PartyS::runOT() {


    //Create an OT input object with the given sigmaArr.
    int elementSize = AES_LENGTH;
    int nOTs = SIZE_OF_NEEDED_BITS;

    OTBatchRInput * input = new OTExtensionRandomizedRInput(s, elementSize);

//    for(int i=0; i<nOTs; i++)
//    {
//        cout<< (int)s[i]<<"--";
//
//    }
    //Run the Ot protocol.
    auto output = otReceiver->transfer(input);
    Q = ((OTOnByteArrayROutput *)output.get())->getXSigma();

//    cout<<"the size is :" <<Q.size()<<endl;
//    for(int i=0; i<nOTs*(elementSize/8); i++){
//
//        if (i%(elementSize/8)==0){
//            cout<<endl;
//        }
//        cout<< (int)Q[i]<<"--";
//
//    }



}
void PartyS::prepareEvalValues(){

    build_tree(evalTree.data(), inputs.data(), 2*numOfItems -1, numOfThreads, prime);

}

void PartyS::recieveCoeffs(int split){

    //recieve the coefficients from R

    vector<byte> polyBytes(numOfItems*SIZE_SPLIT_FIELD_BYTES);

    channel->read((byte*)polyBytes.data(), polyBytes.size());

    BytesToZZ_px(polyBytes.data(), polyP, numOfItems, SIZE_SPLIT_FIELD_BYTES);

    if(FLAG_PRINT)
        cout<<polyP;

}

void PartyS::prepareQ() {//build the rows ti and ui




    vector<byte> partialInputsAsBytesArr(numOfItems * 16);
    setInputsToByteVector(0, numOfItems, partialInputsAsBytesArr);
    //NOTE-----------change to param of the underlying field
    OpenSSLAES aes;
    SecretKey key;


    aesArr.resize(SIZE_OF_NEEDED_BITS);
    for(int i=0; i<SIZE_OF_NEEDED_BITS; i++) {

        key = SecretKey(Q.data() + 16 * i, 16, "aes");

        //cout<<"keyt "<<i<<" " << (int)key.getEncoded()[0]<<endl;
        aesArr[i].setKey(key);

    }


//#pragma omp parallel for
    for(int i=0; i<SIZE_OF_NEEDED_BITS; i++){



        aesArr[i].optimizedCompute(partialInputsAsBytesArr, qbitArr[i]);
       // cout<<"omp_get_num_threads() = " <<    omp_get_num_threads()<<endl;

    }


    //in this stage we have the entire matrix but not with a single bit, rather with 128 bits

    //extract each bit to get the entire row of bits
    byte temp = 0;
    for(int s=0; s<NUM_OF_SPLITS;s++) {
        for(int i=0; i < numOfItems; i++){



            //init the value
            //qRows[i][j] = 0;
            for (int j = 0; j < SPLIT_FIELD_SIZE_BITS; j++) {

                //get first bit from the entires encryption
                temp = qbitArr[SPLIT_FIELD_SIZE_BITS*s+j][i * 16] & 1;


                //get the bit in the right position
                qRows[s][i][j / 8] += (temp << (j % 8));

            }

//            cout<<"temp q" <<i<< " " << (int)(qRows[s][i][0]&1);
//            cout<<endl;
        }

    }

}

void PartyS::setInputsToByteVector(int offset, int numOfItemsToConvert, vector<byte> & inputsAsBytesArr) {


    for (int i = 0; i<numOfItemsToConvert; i++){

        //get only the top 16 bytes of the inputs
        BytesFromZZ(inputsAsBytesArr.data()  + AES_LENGTH_BYTES*(i+offset),rep(inputs[i+offset]),AES_LENGTH_BYTES);

        //field->elementToBytes(inputsAsBytesArr.data()  + AES_LENGTH_BYTES*(i+offset), inputs[i+offset]);


//        cout<<inputs[i] ;
//        cout<<" "<<  (int)*(inputsAsBytesArr.data()+ AES_LENGTH_BYTES*(i+offset))<<endl;
    }

}


void PartyS::sendHashValues(){

    auto all = scapi_now();

    for(int i=0; i<numOfItems; i++) {
        //update the hash
        for(int s=0; s<NUM_OF_SPLITS;s++)
            hash.update(zRows[s][i], 0, SIZE_SPLIT_FIELD_BYTES);

        //at each iteration move the pointer only neededHashSize even though the hash returns the readl hash size
        hash.hashFinal(zSha, i * neededHashSize);
    }

    zSha.resize(numOfItems*neededHashSize);

    //cout<< zRows[i] <<endl;

    auto end = std::chrono::system_clock::now();
    int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
    if(FLAG_PRINT_TIMINGS)
        cout << "   PartyS - eval and prepare to send took " << elapsed_ms << " milliseconds" << endl;

    channel->write(zSha.data(), zSha.size());

}

void PartyS::evalAndSet(int split)  {

    //ZZ prime(2305843009213693951);
    //eval all points
    //multipoint_evaluate_zp(polyP, inputs.data(), yArr.data(), numOfItems - 1);
    evaluate(polyP, evalTree.data(), evalRemainder.data(), 2*numOfItems - 1, yArr.data(), numOfThreads, prime);
    vector<byte> evaluatedElem(SIZE_SPLIT_FIELD_BYTES);

    for(int i=0; i < numOfItems; i++){

        //get the evaluated element as vector;
        BytesFromZZ(evaluatedElem.data(), rep(yArr[i]), SIZE_SPLIT_FIELD_BYTES);



        for(int j=0; j<SIZE_SPLIT_FIELD_BYTES; j++) {

            zRows[split][i][j] = qRows[split][i][j] ^ (evaluatedElem[j] & sElements[SIZE_SPLIT_FIELD_BYTES*split + j]);

            if(FLAG_PRINT)
                cout<<(int) zRows[split][i][j] << " - ";

        }


        if(FLAG_PRINT)
            cout<<endl;




    }
}


