#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 



#include <cryptoTools/Network/Channel.h>
//template<typename ... Args>
//std::string string_format(const std::string& format, Args ... args)
//{
//	size_t size = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
//	std::unique_ptr<char[]> buf(new char[size]);
//	std::snprintf(buf.get(), size, format.c_str(), args ...);
//	return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
//}
void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
