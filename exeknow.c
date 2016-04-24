/*
 *     exeknow.c - Contains the definitions for exeknow
 *     Copyright (C) 2016  Sk. Mohammadul Haque
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "exeknow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void exeknow_error(int type)
{
    switch(type)
    {
    case EXEKNOW_ERROR_FILE_OPEN:
        fprintf(stderr, "Cannot open file.\n");
        exit(-1);
        break;
    case EXEKNOW_ERROR_FILE_READ:
        fprintf(stderr, "Cannot read file.\n");
        exit(-2);
        break;
    case EXEKNOW_ERROR_SIZEMISMATCH:
        fprintf(stderr, "Data size mismatch.\n");
        exit(-3);
        break;
    default:
        fprintf(stderr, "Unknown error.\n");
        exit(-4);
    }
}

const char *exeknow_getfilename(char const *path)
{
#if defined(_WIN32) ||defined(WIN32)
    char *s = strrchr(path, '\\');
#else
    char *s = strrchr(path, '/');
#endif
    if(s==NULL) return path;
    return s+1;
}

int exeknow_get_filetype(FILE* fp)
{
    if(fp!=NULL)
    {
        int type = EXEKNOW_TYPE_UNKNOWN;
        uint8_t etype[4];
        fseek(fp, 0, SEEK_SET);
        if(fread(etype, 4, 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
        if(etype[0]=='M' && etype[1]=='Z') type = EXEKNOW_TYPE_MZ;
        else if(etype[0]==0x7F && etype[1]=='E' && etype[2]=='L' && etype[3]=='F') type = EXEKNOW_TYPE_ELF;
        return type;
    }
    return EXEKNOW_ERROR_FILE_OPEN;
}

void exeknow_get_details_pe(FILE* fp, uint16_t offset)
{
    pe_header peh;
    fseek(fp, offset, SEEK_SET);
    if(fread(&peh, sizeof(pe_header), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);

    if(peh.signature[0]=='P' && peh.signature[1]=='E')
    {
        fprintf(stdout, "------------\nPE Details:\n------------\nMachine: ");
        switch(peh.machine)
        {
        case EXEKNOW_PE_MACHINE_UNKNOWN:
            fprintf(stdout, "Unknown\n");
            break;
        case EXEKNOW_PE_MACHINE_AMD64:
            fprintf(stdout, "AMD64\n");
            break;
        case EXEKNOW_PE_MACHINE_ARM:
            fprintf(stdout, "ARM\n");
            break;
        case EXEKNOW_PE_MACHINE_I386:
            fprintf(stdout, "I386\n");
            break;
        case EXEKNOW_PE_MACHINE_IA64:
            fprintf(stdout, "IA64\n");
            break;
        default:
            fprintf(stdout, "Other\n");
        }
        fprintf(stdout, "Characteristics: ");
        if(peh.characteristics&EXEKNOW_PE_ITYPE_DLL)
        {
            fprintf(stdout, "DLL ");
        }
        if(peh.characteristics&EXEKNOW_PE_ITYPE_EXEC_IM)
        {
            fprintf(stdout, "EXEC ");
        }
        if(peh.characteristics&EXEKNOW_PE_ITYPE_SYSTEM)
        {
            fprintf(stdout, "SYS ");
        }
        if(peh.characteristics&EXEKNOW_PE_ITYPE_RELOC_STRIPPED)
        {
            fprintf(stdout, "RELOCSTRIP ");
        }
        if(peh.characteristics&EXEKNOW_PE_ITYPE_DEBUG_STRIPPED)
        {
            fprintf(stdout, "DEBUGSTRIP ");
        }
        fprintf(stdout, "\n");

        fprintf(stdout, "Number of Sections: %hu\n", peh.num_sections);
    }
}

void exeknow_get_details_ne(FILE* fp, uint16_t offset)
{
    ne_header neh;
    fseek(fp, offset, SEEK_SET);
    if(fread(&neh, sizeof(ne_header), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
    if(neh.signature[0]=='N' && neh.signature[1]=='E')
    {
        fprintf(stdout, "------------\nNE Details:\n------------\nMachine: ");
        switch(neh.prog_flags)
        {
        case 0x01:
            fprintf(stdout, "I286+\n");
            break;
        case 0x02:
            fprintf(stdout, "I386+\n");
            break;
        case 0x03:
            fprintf(stdout, "I486+\n");
            break;
        case 0x04:
            fprintf(stdout, "I586+\n");
            break;
        case 0x20:
            fprintf(stdout, "I860(N10)\n");
            break;
        case 0x21:
            fprintf(stdout, "N11\n");
            break;
        case 0x40:
            fprintf(stdout, "MIPS Mark I\n");
            break;
        case 0x41:
            fprintf(stdout, "MIPS Mark II\n");
            break;
        case 0x42:
            fprintf(stdout, "MIPS Mark III\n");
            break;
        default:
            fprintf(stdout, "Other\n");
        }
        switch(neh.target_os)
        {
        case 0x01:
            fprintf(stdout, "OS: OS/2\n");
            break;
        case 0x02:
            fprintf(stdout, "OS: Windows\n");
            break;
        case 0x03:
            fprintf(stdout, "OS: DOS 4.x\n");
            break;
        case 0x04:
            fprintf(stdout, "OS: Windows 386\n");
            break;
        default:
            fprintf(stdout, "OS: Other\n");
        }
        fprintf(stdout, "Number of Segments: %hu\n", neh.num_segs);
        fprintf(stdout, "DGroup: ");
        switch(neh.prog_flags&0x3)
        {
        case EXEKNOW_NE_PROGTYPE_NONE:
            fprintf(stdout, "NONE\n");
            break;
        case EXEKNOW_NE_PROGTYPE_SINSHARED:
            fprintf(stdout, "SINGLESHARED\n");
            break;
        case EXEKNOW_NE_PROGTYPE_MULTIPLE:
            fprintf(stdout, "MULTIPLE\n");
            break;
        }
        fprintf(stdout, "Machine: ");
        if(neh.appl_flags&0x10)
        {
            fprintf(stdout, "8086 ");
        }
        if(neh.appl_flags&0x20)
        {
            fprintf(stdout, "80286 ");
        }
        if(neh.appl_flags&0x40)
        {
            fprintf(stdout, "80386 ");
        }
        if(neh.appl_flags&0x80)
        {
            fprintf(stdout, "80x87 ");
        }
        fprintf(stdout, "\nCharacteristics: ");
        if(neh.appl_flags&EXEKNOW_NE_DLL)
        {
            fprintf(stdout, "DLL ");
        }
        if(neh.appl_flags&EXEKNOW_NE_OS2_FAMILY)
        {
            fprintf(stdout, "OS2 ");
        }
        fprintf(stdout, "\n");
    }
}

void exeknow_get_details_le(FILE* fp, uint16_t offset)
{
    le_header leh;
    fseek(fp, offset, SEEK_SET);
    if(fread(&leh, sizeof(le_header), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
    if(leh.signature[0]=='L' && leh.signature[1]=='E')
    {
        fprintf(stdout, "------------\nLE Details:\n------------\nMachine: ");
        switch(leh.cpu_type)
        {
        case 0x01:
            fprintf(stdout, "I286+\n");
            break;
        case 0x02:
            fprintf(stdout, "I386+\n");
            break;
        case 0x03:
            fprintf(stdout, "I486+\n");
            break;
        case 0x04:
            fprintf(stdout, "I586+\n");
            break;
        case 0x20:
            fprintf(stdout, "I860(N10)\n");
            break;
        case 0x21:
            fprintf(stdout, "N11\n");
            break;
        case 0x40:
            fprintf(stdout, "MIPS Mark I\n");
            break;
        case 0x41:
            fprintf(stdout, "MIPS Mark II\n");
            break;
        case 0x42:
            fprintf(stdout, "MIPS Mark III\n");
            break;
        default:
            fprintf(stdout, "Other\n");
        }
        switch(leh.target_os)
        {
        case 0x01:
            fprintf(stdout, "OS: OS/2\n");
            break;
        case 0x02:
            fprintf(stdout, "OS: Windows\n");
            break;
        case 0x03:
            fprintf(stdout, "OS: DOS 4.x\n");
            break;
        case 0x04:
            fprintf(stdout, "OS: Windows 386\n");
            break;
        default:
            fprintf(stdout, "OS: Other\n");
        }
        fprintf(stdout, "Number of Pages: %hu\n", leh.num_pages);
        fprintf(stdout, "Characteristics: ");
        if(leh.characteristics&EXEKNOW_LE_ITYPE_LOADABLE)
        {
            fprintf(stdout, "LOADABLE ");
        }
        if(leh.characteristics&EXEKNOW_LE_ITYPE_DLL)
        {
            fprintf(stdout, "DLL\n");
        }
        else fprintf(stdout, "EXEC\n");

    }
}

int exeknow_get_details_mz(FILE* fp)
{
    if(fp!=NULL)
    {
        mz_header mzh;
        uint16_t exe_offset;
        uint8_t exe_type[2];
        fseek(fp, 0, SEEK_SET);
        if(fread(&mzh, sizeof(mz_header), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
        if(mzh.signature[0]=='M' && mzh.signature[1]=='Z')
        {
            fprintf(stdout, "------------\nMZ Details:\n------------\n");
            fprintf(stdout, "Number of Blocks: %hu\n", mzh.blocks_in_file);
            fprintf(stdout, "Number of Relocations: %hu\n", mzh.num_relocs);
            fseek(fp, 0x3C, SEEK_SET);
            if(fread(&exe_offset, sizeof(uint16_t), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
            fseek(fp, exe_offset, SEEK_SET);
            if(fread(&exe_type, sizeof(uint8_t), 2, fp)!=2) exeknow_error(EXEKNOW_ERROR_FILE_READ);
            if(exe_type[0]=='M' && exe_type[1]=='Z')
            {
                fprintf(stdout, "Format: Plain MZ\n");
            }
            else if(exe_type[0]=='P' && exe_type[1]=='E')
            {
                fprintf(stdout, "Format: PE\n");
                exeknow_get_details_pe(fp, exe_offset);
            }
            else if(exe_type[0]=='L' && exe_type[1]=='E')
            {
                fprintf(stdout, "Format: LE\n");
                exeknow_get_details_le(fp, exe_offset);
            }
            else
            {
                fprintf(stdout, "Format: Other\n");
            }
            fseek(fp, 0L, SEEK_SET);
            return 0;
        }
        return EXEKNOW_ERROR_BAD_FTYPE;
    }
    return EXEKNOW_ERROR_FILE_OPEN;
}

int exeknow_get_details_elf(FILE* fp)
{
    if(fp!=NULL)
    {
        elf_header elh;
        fseek(fp, 0, SEEK_SET);
        if(fread(&elh, sizeof(elf_header), 1, fp)!=1) exeknow_error(EXEKNOW_ERROR_FILE_READ);
        if(elh.ident[0]==0x7F && elh.ident[1]=='E' && elh.ident[2]=='L' && elh.ident[3]=='F')
        {
            fprintf(stdout, "------------\nELF Details:\n------------\n");
            fprintf(stdout, "Version: %hu\nArchitecture: ", elh.ident[6]);

            switch(elh.ident[4])
            {
            case 1:
                fprintf(stdout, "32bit\nMachine: ");
                break;
            case 2:
                fprintf(stdout, "64bit\nMachine: ");
                break;
            default:
                fprintf(stdout, "Invalid\nMachine: ");
                break;
            }
            switch(elh.machine)
            {
            case EXEKNOW_ELF_MACHINE_ARM:
                fprintf(stdout, "ARM\n");
                break;
            case EXEKNOW_ELF_MACHINE_I386:
                fprintf(stdout, "I386\n");
                break;
            case EXEKNOW_ELF_MACHINE_I860:
                fprintf(stdout, "I860\n");
                break;
            case EXEKNOW_ELF_MACHINE_I960:
                fprintf(stdout, "I960\n");
                break;
            case EXEKNOW_ELF_MACHINE_IA64:
                fprintf(stdout, "IA64\n");
                break;
            case EXEKNOW_ELF_MACHINE_M32:
                fprintf(stdout, "M32\n");
                break;
            case EXEKNOW_ELF_MACHINE_MIPS:
                fprintf(stdout, "MIPS\n");
                break;
            case EXEKNOW_ELF_MACHINE_PPC:
                fprintf(stdout, "PPC\n");
                break;
            case EXEKNOW_ELF_MACHINE_SPARC:
                fprintf(stdout, "SPARC\n");
                break;
            case EXEKNOW_ELF_MACHINE_SPARC32PLUS:
                fprintf(stdout, "SPARC32+\n");
                break;
            case EXEKNOW_ELF_MACHINE_SPARC9:
                fprintf(stdout, "SPARC9\n");
                break;
            default:
                fprintf(stdout, "Other\n");
            }
            fprintf(stdout, "Type: ");
            switch(elh.type)
            {
            case 0:
                fprintf(stdout, "Unknown");
                break;
            case 1:
                fprintf(stdout, "RELOC");
                break;
            case 2:
                fprintf(stdout, "EXEC");
                break;
            case 3:
                fprintf(stdout, "DLL");
                break;
            case 4:
                fprintf(stdout, "CORE");
                break;
            }
            fprintf(stdout, "\n");
            fseek(fp, 0L, SEEK_SET);
            return 0;
        }
        return EXEKNOW_ERROR_BAD_FTYPE;
    }
    return EXEKNOW_ERROR_FILE_OPEN;
}

int exeknow_get_details(FILE* fp, int ftype, const char* fname)
{
    int ret = EXEKNOW_OK;
    fseek(fp, 0L, SEEK_END);
    fprintf(stdout, "------------\nFile Details:\n------------\n");
    fprintf(stdout, "Executable Name: %s\n", exeknow_getfilename(fname));
    fprintf(stdout, "Executable Size: %ld bytes\n", ftell(fp));
    fprintf(stdout, "Executable Type: ");
    switch(ftype)
    {
    case EXEKNOW_TYPE_MZ:
        fprintf(stdout, "MZ\n");
        exeknow_get_details_mz(fp);
        break;
    case EXEKNOW_TYPE_ELF:
        fprintf(stdout, "ELF\n");
        exeknow_get_details_elf(fp);
        break;
    default:
        fprintf(stdout, "Unknown\n");
        ret = EXEKNOW_ERROR_BAD_FTYPE;
    }
    return ret;
}

void exeknow_know(const char* fname)
{
    FILE* fp = NULL;
    int ftype;
    if((fp = fopen(fname, "rb"))==NULL) exeknow_error(EXEKNOW_ERROR_FILE_OPEN);
    ftype = exeknow_get_filetype(fp);
    exeknow_get_details(fp, ftype, fname);
}
