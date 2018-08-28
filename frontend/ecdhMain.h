#pragma once




#include <vector> 
#include "cryptoTools/Common/Defines.h"
#include "util.h"


void EcdhSend(int curveType, int setSize, int mTrials);
void EcdhRecv(int curveType, int setSize, int mTrials);

