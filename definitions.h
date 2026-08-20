#pragma once

#include <Windows.h>
#include <cstdint>


typedef struct _CoffHeader {
    unsigned short    machine;
    unsigned short    numberOfSections;
    unsigned int    timeDateStamp;
    unsigned int    pointerToSymbolTable;
    unsigned int    numberOfSymbols;
    unsigned short    sizeOfOptionalHeader;
    unsigned short    characteristics;
} COFFHeader, * PCOFFHeader;

// IMAGE_SYMBOL is symbol struct 


typedef struct _CoffReloc {
    uint32_t    virtualAddress;
    uint32_t    symbolTableIndex;
    uint16_t    type;
} CoffReloc, * PCoffReloc;


