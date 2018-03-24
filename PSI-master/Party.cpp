//
// Created by moriya on 04/02/18.
//

#include "Party.h"

Party::Party(int argc, char* argv []) : Protocol("PSI", argc, argv)
{
    numOfItems = stoi(this->getParser().getValueByKey(arguments, "numOfItems"));
    times = stoi(this->getParser().getValueByKey(arguments,"internalIterationsNumber"));
    numOfThreads = stoi(this->getParser().getValueByKey(arguments,"numOfThreads"));


    NUM_OF_SPLITS = numOfItems;
    SPLIT_FIELD_SIZE_BITS = stoi(this->getParser().getValueByKey(arguments, "fieldSize"));
    SIZE_SPLIT_FIELD_BYTES = SPLIT_FIELD_SIZE_BITS/8 + 1;
    SIZE_OF_NEEDED_BITS = NUM_OF_SPLITS * SPLIT_FIELD_SIZE_BITS;
    SIZE_OF_NEEDED_BYTES = SIZE_SPLIT_FIELD_BYTES*NUM_OF_SPLITS;

    neededHashSize =  (40 + 2*log2(numOfItems) +7)/8;//hash.getHashedMsgSize()
}

Party::~Party()
{
    delete timer;
}