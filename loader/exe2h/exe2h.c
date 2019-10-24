/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include <shlwapi.h>
#include "mmap.h"
#pragma comment(lib, "shlwapi.lib")
#else
#define NIX
#include <libgen.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pe.h>
#endif

// return pointer to DOS header
PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT header
PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
int is64 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER SecHdr (void *map) {
    PIMAGE_NT_HEADERS nt = NtHdr(map);
  
    return (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader + 
    nt->FileHeader.SizeOfOptionalHeader);
}

uint32_t DirSize (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->NumberOfRvaAndSizes;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->NumberOfRvaAndSizes;
    }
}

uint32_t SecSize (void *map) {
    return NtHdr(map)->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

uint64_t ImgBase (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->ImageBase;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->ImageBase;
    }
}

// valid dos header?
int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
}

uint32_t rva2ofs (void *map, uint32_t rva) {
    int i;
    
    PIMAGE_SECTION_HEADER sh = SecHdr(map);
    
    for (i=0; i<SecSize(map); i++) {
      if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData)
      return sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
    }
    return -1;
}

void bin2h(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint8_t   *p=(uint8_t*)bin;
    FILE      *fd;
    
    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));
    
#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 16;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }
    if(map != NULL) {
      strcat(label, is32(map) ? "_X86" : "_X64");
      strcat(file,  is32(map) ? "_x86" : "_x64");
    }
    strcat(file, ".h");
    
    fd = fopen(file, "wb");
    
    if(fd != NULL) {
      fprintf(fd, "\nunsigned char %s[] = {", label);
      
      for(i=0;i<len;i++) {
        if(!(i % 12)) fprintf(fd, "\n  ");
        fprintf(fd, "0x%02x", p[i]);
        if((i+1) != len) fprintf(fd, ", ");
      }
      fprintf(fd, "};\n\n");
      fclose(fd);
      printf("  [ saved code to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);
}

void bin2go(void* map, char* fname, void* bin, uint32_t len) {
	char      label[32], file[32], * str;
	uint32_t  i;
	uint8_t* p = (uint8_t*)bin;
	FILE* fd;

	memset(label, 0, sizeof(label));
	memset(file, 0, sizeof(file));

#if defined(WINDOWS)
	str = PathFindFileName(fname);
#else
	str = basename(fname);
#endif
	for (i = 0; str[i] != 0 && i < 16; i++) {
		if (str[i] == '.') {
			file[i] = label[i] = '_';
		}
		else {
			label[i] = toupper(str[i]);
			file[i] = tolower(str[i]);
		}
	}
	if (map != NULL) {
		strcat(label, is32(map) ? "_X86" : "_X64");
		strcat(file, is32(map) ? "_x86" : "_x64");
	}
	strcat(file, ".go");

	fd = fopen(file, "wb");

	if (fd != NULL) {
		fprintf(fd, "package donut\n\n// %s - stub for EXE PE files\nvar %s = []byte{\n", label, label);
		
		for (i = 0; i < len; i++) {
			if (!(i % 12)) fprintf(fd, "\n  ");
			fprintf(fd, "0x%02x", p[i]);
			if ((i + 1) != len) fprintf(fd, ", ");
		}
		fprintf(fd, "};\n\n");
		fclose(fd);
		printf("  [ saved code to %s\n", file);
	}
	else printf("  [ unable to create file : %s\n", file);
}


/**
void bin2array(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint32_t  *p=(uint32_t*)bin;
    FILE      *fd;
    
    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));
    
#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 16;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }
    
    strcat(file, ".h");
    
    fd = fopen(file, "wb");
    
    if(fd != NULL) {
      // align up by 4
      len = (len & -4) + 4;
      len >>= 2;
      
      // declare the array
      fprintf(fd, "\nunsigned int %s[%i];\n\n", label, len);
    
      // initialize array
      for(i=0; i<len; i++) {
        fprintf(fd, "%s[%i] = 0x%08" PRIX32 ";\n", label, i, p[i]);
      }
      fclose(fd);
      printf("  [ Saved array to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);    
}
*/
// structure of COFF (.obj) file

//--------------------------//
// IMAGE_FILE_HEADER        //
//--------------------------//
// IMAGE_SECTION_HEADER     //
//  * num sections          //
//--------------------------//
//                          //
//                          //
//                          //
// section data             //
//  * num sections          //
//                          //
//                          //
//--------------------------//
// IMAGE_SYMBOL             //
//  * num symbols           //
//--------------------------//
// string table             //
//--------------------------//

int main (int argc, char *argv[]) {
    int                        fd, i;
    struct stat                fs;
    uint8_t                    *map, *cs;
    PIMAGE_SECTION_HEADER      sh;
    //PIMAGE_FILE_HEADER         fh;
    //PIMAGE_COFF_SYMBOLS_HEADER csh;
    uint32_t                   ofs, len;
    
    if (argc != 2) {
      printf ("\n  [ usage: file2h <file.exe | file.bin>\n");
      return 0;
    }
    
    // open file for reading
    fd = open(argv[1], O_RDONLY);
    
    if(fd == 0) {
      printf("  [ unable to open %s\n", argv[1]);
      return 0;
    }
    // if file has some data
    if(fstat(fd, &fs) == 0) {
      // map into memory
      map = (uint8_t*)mmap(NULL, fs.st_size,  
        PROT_READ, MAP_PRIVATE, fd, 0);
      if(map != NULL) {
        if(valid_dos_hdr(map) && valid_nt_hdr(map)) {
          printf("  [ Found valid DOS and NT header.\n");
          // get the .text section
          sh = SecHdr(map);
          // if a section header was returned
          if(sh != NULL) {
            printf("  [ Locating .text section.\n");
            // locate the .text section
            for(i=0; i<SecSize(map); i++) {
              if(strcmp((char*)sh[i].Name, ".text") == 0) {
                ofs = rva2ofs(map, sh[i].VirtualAddress);
                
                if(ofs != -1) {
                  cs  = (map + ofs);
                  len = sh[i].Misc.VirtualSize;
                  // convert to header file
                  bin2h(map, argv[1], cs, len);
				  bin2go(map, argv[1], cs, len);
                  break;
                }
              }
            }
          }
        } else {
          printf("  [ No valid DOS or NT header found.\n");
          // treat file as binary
          bin2h(NULL, argv[1], map, fs.st_size);
		  bin2go(NULL, argv[1], map, fs.st_size);
          //bin2array(NULL, argv[1], map, fs.st_size);
        }
        munmap(map, fs.st_size);
      }
    }
    close(fd);
    return 0;
}
