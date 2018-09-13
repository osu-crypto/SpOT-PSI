#pragma once




#include <vector> 
#include "cryptoTools/Common/Defines.h"
#include "util.h"
#include <string>


void EcdhSend(int curveType, int setSize, std::string ipAdress, int mTrials);
void EcdhRecv(int curveType, int setSize, std::string ipAdress, int mTrials);

