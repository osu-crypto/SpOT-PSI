//
// Created by moriya on 01/10/17.
//

#include "Mersenne.hpp"

//template <>
//TemplateField<ZpMersenneIntElement>::TemplateField(long fieldParam) {
//
//    this->fieldParam = 2147483647;
//    this->elementSizeInBytes = 4;//round up to the next byte
//    this->elementSizeInBits = 31;
//
//    auto randomKey = prg.generateKey(128);
//    prg.setKey(randomKey);
//
//    m_ZERO = new ZpMersenneIntElement(0);
//    m_ONE = new ZpMersenneIntElement(1);
//}
//
//template <>
//TemplateField<ZpMersenneLongElement>::TemplateField(long fieldParam) {
//
//    this->elementSizeInBytes = 8;//round up to the next byte
//    this->elementSizeInBits = 61;
//
//    auto randomKey = prg.generateKey(128);
//    prg.setKey(randomKey);
//
//    m_ZERO = new ZpMersenneLongElement(0);
//    m_ONE = new ZpMersenneLongElement(1);
//}


template <>
ZpMersenneIntElement TemplateField<ZpMersenneIntElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpMersenneIntElement element(b);
        return element;
    }
}


template <>
ZpMersenneLongElement TemplateField<ZpMersenneLongElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpMersenneLongElement element(b);
        return element;
    }
}

template <>
void TemplateField<ZpMersenneIntElement>::elementToBytes(unsigned char* elemenetInBytes, ZpMersenneIntElement& element){

    memcpy(elemenetInBytes, (byte*)(&element.elem), 4);
}

template <>
void TemplateField<ZpMersenneLongElement>::elementToBytes(unsigned char* elemenetInBytes, ZpMersenneLongElement& element){

    memcpy(elemenetInBytes, (byte*)(&element.elem), 8);
}

//template <>
//void TemplateField<ZpMersenneIntElement>::elementVectorToByteVector(vector<ZpMersenneIntElement> &elementVector, vector<byte> &byteVector){
//
//    copy_byte_array_to_byte_vector((byte *)elementVector.data(), elementVector.size()*elementSizeInBytes, byteVector,0);
//}
//
//template <>
//void TemplateField<ZpMersenneLongElement>::elementVectorToByteVector(vector<ZpMersenneLongElement> &elementVector, vector<byte> &byteVector){
//
//    copy_byte_array_to_byte_vector((byte *)elementVector.data(), elementVector.size()*elementSizeInBytes, byteVector,0);
//}


template <>
ZpMersenneIntElement TemplateField<ZpMersenneIntElement>::bytesToElement(unsigned char* elemenetInBytes){

    return ZpMersenneIntElement((unsigned int)(*(unsigned int *)elemenetInBytes));
}


template <>
ZpMersenneLongElement TemplateField<ZpMersenneLongElement>::bytesToElement(unsigned char* elemenetInBytes){

    return ZpMersenneLongElement((unsigned long)(*(unsigned long *)elemenetInBytes));
}
