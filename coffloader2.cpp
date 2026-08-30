// coffloader2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <filesystem>
#include "definitions.h"
#include "pystring.h"
#include "helpers.h"



extern "C" void printchar(char* s) {
    printf("%s", s);
   
}



int main()
{
   
	
    auto filename = "C:\\Users\\NIKHIL\\source\\repos\\boftest\\boftest.o";
    std::ifstream fd;
    fd.open(filename, std::ios::binary);

    if (!fd.is_open()) {
        std::cout << "unable to open file\n";
        return 0;
    }
    

    auto filesize = std::filesystem::file_size(filename);

    std::vector<char> buffer(filesize, 0);

    fd.read(buffer.data(), filesize);

    fd.close();





// <image url="$(ProjectDir)coffheader.png" scale="1.0"/>
    
    
    COFFHeader coffheader = *(PCOFFHeader)(buffer.data());

    std::cout << "size of coffheader: " << std::dec<< sizeof(COFFHeader) << std::endl;

    if (coffheader.machine != 0x8664) {
        std::cout << "Not 64bit object file\n";
        return 0;       
    }

    std::vector<IMAGE_SECTION_HEADER> sectionheaders;
    sectionheaders.reserve(coffheader.numberOfSections);

    
    
    std::cout << "size of sectionheader: " << sizeof(IMAGE_SECTION_HEADER) << std::endl;


// <image url="$(ProjectDir)sectionheaders.png" scale="1.0"/>



    PIMAGE_SECTION_HEADER sectionheaderptr = (PIMAGE_SECTION_HEADER)((char*)buffer.data() + sizeof(COFFHeader));
    for (int i = 0;i < coffheader.numberOfSections;i++) {

        std::cout << "pointer to raw data: " << sectionheaderptr->PointerToRawData << std::endl;
        std::cout << "Size of raw data: " << sectionheaderptr->SizeOfRawData << std::endl;
        std::cout << "Number of relocations: " << sectionheaderptr->NumberOfRelocations << std::endl;
        std::cout << "Pointer to relocations: " << sectionheaderptr->PointerToRelocations << std::endl;
        std::cout << "section count: " << i << std::endl;
        std::cout << "\n";
        sectionheaders.push_back(*sectionheaderptr);

        
        sectionheaderptr++;
    }

    std::vector<IMAGE_SYMBOL> symboltable;
    symboltable.reserve(coffheader.numberOfSymbols);
    

// <image url="$(ProjectDir)symbolandstring.png" scale="1.0"/>
    


    PIMAGE_SYMBOL symbolptr = (PIMAGE_SYMBOL)((char*)buffer.data() + coffheader.pointerToSymbolTable);
    std::cout << "Number of symbols: " << coffheader.numberOfSymbols << std::endl;
    std::cout << "symbol pointer: " << coffheader.pointerToSymbolTable << std::endl;
    PVOID stringptr = ((char*)buffer.data() + coffheader.pointerToSymbolTable +
        (coffheader.numberOfSymbols*sizeof(IMAGE_SYMBOL)));
    std::cout << "string table pointer: " << coffheader.pointerToSymbolTable +
        (coffheader.numberOfSymbols * sizeof(IMAGE_SYMBOL)) << std::endl;

    for (int i = 0;i < coffheader.numberOfSymbols;i++) {


        symboltable.push_back(*symbolptr);


        symbolptr++;

    }

   

    // allocating sections
    std::vector<LPVOID> sectionbases;
    sectionbases.reserve(coffheader.numberOfSections);
    
    for (const auto sectionheader : sectionheaders) {

        auto baseaddress = VirtualAlloc(NULL, sectionheader.SizeOfRawData, 
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        // copying section data into allocated memory
        memcpy(baseaddress, (char*)buffer.data() + sectionheader.PointerToRawData,
            sectionheader.SizeOfRawData);

        
        sectionbases.push_back(baseaddress);

    }

    auto kernel32base = getdllbaseaddress("kernel32.dll");

    ULONGLONG loadlibraryaddr = getdllexportfunctionaddress(kernel32base, "LoadLibraryA");
    ULONGLONG getprocaddress = getdllexportfunctionaddress(kernel32base, "GetProcAddress");
    ULONGLONG virtualprotectaddr = getdllexportfunctionaddress(kernel32base, "VirtualProtect");

    std::cout << "Address of printchar: " << printchar << std::endl;

    // relocations
    for (int i = 0;i < sectionheaders.size(); i++) {

        PIMAGE_RELOCATION relocptr = (PIMAGE_RELOCATION)((char*)buffer.data() + sectionheaders[i].PointerToRelocations);
        for (int j = 0;j < sectionheaders[i].NumberOfRelocations;j++) {

                
            auto symboltableindex = relocptr->SymbolTableIndex;
            auto reloctype = relocptr->Type;
            auto patchaddress = (char*)sectionbases[i] + relocptr->VirtualAddress;
            std::cout << "\n";
            std::cout << "section base: " << sectionbases[i] << std::endl;
            std::cout << "patchaddress rva: " << relocptr->VirtualAddress << std::endl;

            //std::cout << "Symbol index: " << std::hex<<symboltableindex << std::endl;
            

            
            if (symboltable[symboltableindex].StorageClass == IMAGE_SYM_CLASS_EXTERNAL ) {
                

                if (symboltable[symboltableindex].SectionNumber == 0) {
                    // symbol does not present in any section, we need to load
                    // eg: getprocaddress() 
                    std::string symname;
                    if (symboltable[symboltableindex].N.Name.Short == 0) {
                        // long name more than 8 characters
                        auto symbolnameptr = (char*)stringptr + symboltable[symboltableindex].N.LongName[1];

                        symname = symbolnameptr;

                    }
                    else {
                        symname = (char*)symboltable[symboltableindex].N.ShortName[0];
                    }
                    std::cout << "External symbol name: " << symname << std::endl;

                    std::string ogsymbolname = symname;
                    std::string symbolname = pystring::lower(symname);
                                            
                    
                    ULONGLONG symboladdress = 0;
                    std::cout << "kernel32base : " <<std::hex<< kernel32base << std::endl;
                    
                    
                    if (ogsymbolname.contains("printchar")) {
                        
                        std::cout << "its printchar\n";
                       
                        std::cout << "reloctype: " << reloctype << std::endl;
                        auto base = VirtualAlloc(NULL, 8, MEM_RESERVE | MEM_COMMIT,
                            PAGE_READWRITE);
                        std::cout << "base: " << base << std::endl;
                        void* fn = reinterpret_cast<void*>(printchar);
                        memcpy(base, &fn, 8);
                        symboladdress = (ULONGLONG)base;
                        patchnormaladdress(patchaddress, symboladdress, reloctype, sectionbases[i]);
                        continue;
                    }

                    
                         auto dllname = pystring::split( pystring::split(ogsymbolname, "$")[0],"?")[1] + ".dll";
                         auto funcname = pystring::split(pystring::split(ogsymbolname, "$")[1], "@")[0];
                         std::cout << "DLLname:  " << dllname << std::endl;
                         std::cout << "functionname: " << funcname << std::endl;
                         
                         

                       
                             auto dllhandle = ((HMODULE(*)(LPCSTR))loadlibraryaddr)(dllname.c_str());

                             if (dllhandle) {
                                 auto funcaddr = ((FARPROC(*)(HMODULE, LPCSTR))getprocaddress)(dllhandle, funcname.c_str());
                                 std::cout << "Address of " << ogsymbolname << " : " << funcaddr << std::endl;
                                 if (funcaddr) {
                                     auto base = VirtualAlloc(NULL, 8, MEM_RESERVE | MEM_COMMIT,
                                         PAGE_READWRITE);
                                     void* fn = reinterpret_cast<void*>(funcaddr);
                                     memcpy(base, &fn, 8);
                                     symboladdress = (ULONGLONG)base;
                                     patchnormaladdress(patchaddress, symboladdress, reloctype, sectionbases[i]);
                                 }
                             }
                         
                         
                         
                    

                    // patching
                    //patchnormaladdress(patchaddress, symboladdress, reloctype, sectionbases[i]);


                }
                
                
                if (symboltable[symboltableindex].SectionNumber != 0) {
                    
                    // offset within section base

                    std::cout << "section number: " << symboltable[symboltableindex].SectionNumber << std::endl;

                    auto symboladdress = (ULONGLONG)sectionbases[symboltable[symboltableindex].SectionNumber - 1]
                        + symboltable[symboltableindex].Value; 



                    patchnormaladdress(patchaddress, symboladdress, reloctype, sectionbases[i]);


                }

            }



            else if (symboltable[symboltableindex].StorageClass == IMAGE_SYM_CLASS_STATIC) {

                std::string symname;
                if (symboltable[symboltableindex].N.Name.Short == 0) {
                    // long name more than 8 characters
                    auto symbolnameptr = (char*)stringptr + symboltable[symboltableindex].N.LongName[1];

                    symname = symbolnameptr;

                }
                else {
                    symname = (char*)symboltable[symboltableindex].N.ShortName;
                }
                std::cout << "Static symbol name: " << symname << std::endl;


                auto symboladdress = (ULONGLONG)sectionbases[symboltable[symboltableindex].SectionNumber - 1]
                    + symboltable[symboltableindex].Value;

                std::cout << "symbol bytes: " << (char*)symboladdress << std::endl;
                std::cout << "reloctype: " << reloctype << std::endl;
                patchnormaladdress(patchaddress, symboladdress, reloctype, sectionbases[i]);


            }




            relocptr++;
        }

    }


    for (const auto symbol : symboltable) {

        std::string symname;
        if (symbol.N.Name.Short == 0) {
            // long name more than 8 characters
            auto symbolnameptr = (char*)stringptr + symbol.N.LongName[1];

            symname = symbolnameptr;

        }
        else {
            symname = (char*)symbol.N.ShortName;
        }
        //std::cout << "symbol name: " << symname << std::endl;
        //std::cout << "symbol value: " << symbol.Value << std::endl;
        if (symname == "go") {

            auto addr = (char*)sectionbases[symbol.SectionNumber - 1] + symbol.Value;


            for (int i = 0; i < sectionheaders.size();i++) {

                
                modifysectionprotection(&sectionheaders[i], sectionbases[i], virtualprotectaddr);

                

            }

            ((void(*)())addr)();

            std::cout << "returned from go\n";

        }

    }




    for (auto sectionbase : sectionbases) {
        VirtualFree(sectionbase, 0, MEM_RELEASE);
    }


}

