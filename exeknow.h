/*
 *     exeknow.h - Contains the declarations for exeknow
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

#ifndef EXEKNOW_H_INCLUDED
#define EXEKNOW_H_INCLUDED

#include <stdint.h>
#include <stdio.h>

#define EXEKNOW_OK (0)

#define EXEKNOW_TYPE_UNKNOWN (-1)
#define EXEKNOW_TYPE_MZ (1)
#define EXEKNOW_TYPE_ELF (2)
#define EXEKNOW_TYPE_E32 (3)

#define EXEKNOW_ERROR_FILE_OPEN (-1)
#define EXEKNOW_ERROR_FILE_READ (-2)
#define EXEKNOW_ERROR_SIZEMISMATCH (-3)
#define EXEKNOW_ERROR_BAD_FTYPE (-4)

#define EXEKNOW_PE_MACHINE_UNKNOWN (0)
#define EXEKNOW_PE_MACHINE_AMD64 (0x8664)
#define EXEKNOW_PE_MACHINE_ARM (0x1c0)
#define EXEKNOW_PE_MACHINE_I386 (0x14c)
#define EXEKNOW_PE_MACHINE_IA64 (0x200)

#define EXEKNOW_NE_OS2_FAMILY (0x8)
#define EXEKNOW_NE_DLL (0x80)

#define EXEKNOW_NE_PROGTYPE_NONE (0x0)
#define EXEKNOW_NE_PROGTYPE_SINSHARED (0x1)
#define EXEKNOW_NE_PROGTYPE_MULTIPLE (0x2)

#define EXEKNOW_PE_ITYPE_RELOC_STRIPPED (0x0001)
#define EXEKNOW_PE_ITYPE_EXEC_IM (0x0002)
#define EXEKNOW_PE_ITYPE_DEBUG_STRIPPED (0x0200)
#define EXEKNOW_PE_ITYPE_SYSTEM (0x1000)
#define EXEKNOW_PE_ITYPE_DLL (0x2000)

#define EXEKNOW_LE_ITYPE_LOADABLE (0x2000)
#define EXEKNOW_LE_ITYPE_DLL (0xF000)

#define EXEKNOW_ELF_ITYPE_NONE (0)
#define EXEKNOW_ELF_ITYPE_RELOC (1)
#define EXEKNOW_ELF_ITYPE_EXEC (2)
#define EXEKNOW_ELF_ITYPE_DLL (3)
#define EXEKNOW_ELF_ITYPE_CORE (4)

#define EXEKNOW_ELF_MACHINE_M32 (1)
#define EXEKNOW_ELF_MACHINE_SPARC (2)
#define EXEKNOW_ELF_MACHINE_I386 (3)
#define EXEKNOW_ELF_MACHINE_I860 (7)
#define EXEKNOW_ELF_MACHINE_MIPS (8)
#define EXEKNOW_ELF_MACHINE_SPARC32PLUS (18)
#define EXEKNOW_ELF_MACHINE_I960 (19)
#define EXEKNOW_ELF_MACHINE_PPC (20)
#define EXEKNOW_ELF_MACHINE_ARM (40)
#define EXEKNOW_ELF_MACHINE_SPARC9 (43)
#define EXEKNOW_ELF_MACHINE_IA64 (50)
#define EXEKNOW_ELF_MACHINE_AMDx86_64 (62)
#define EXEKNOW_ELF_MACHINE_AVR8 (83)
#define EXEKNOW_ELF_MACHINE_AVR32 (185)

#define EXEKNOW_E32_ITYPE_DLL (0x00000001)
#define EXEKNOW_E32_IMP_FORMAT (0xF0)
#define EXEKNOW_E32_ABI (0x18)
#define EXEKNOW_E32_ENTRYPOINT_TYPE (0xE0)

typedef struct mz_header
{
    uint8_t signature[2];/**< Magic number MZ */
    uint16_t bytes_in_last_block; /**< Bytes on last block of file */
    uint16_t blocks_in_file; /**< Blocks in file */
    uint16_t num_relocs; /**< Number of relocations */
    uint16_t header_paragraphs; /**< Size of header in paragraphs */
    uint16_t min_extra_paragraphs; /**< Minimum extra paragraphs needed */
    uint16_t max_extra_paragraphs; /**< Maximum extra paragraphs needed */
    uint16_t ss; /**< Initial (relative) SS value */
    uint16_t sp; /**< Initial SP value */
    uint16_t checksum; /**< Checksum */
    uint16_t ip; /**< Initial IP value */
    uint16_t cs; /**< Initial (relative) CS value */
    uint16_t reloc_table_offset; /**< File address of relocation table */
    uint16_t overlay_number; /**< Overlay number */
} mz_header; /**< MZ header */

typedef struct pe_header
 {
    uint8_t signature[2]; /**< Magic number PE */
    uint8_t byte_order; /**< Byte order */
    uint8_t word_order; /**< Word order */
    uint16_t machine; /**< Target machine */
    uint16_t num_sections; /**< Size of section table */
    uint32_t timedate_stamp; /**< Time and date stamp */
    uint32_t pointer_symtable; /**< File offset of symbol table */
    uint32_t num_symbols; /**< Number of symbols */
    uint16_t size_optionalheader; /**< Size of optional header */
    uint16_t characteristics; /**< Characteristic flags */
 } pe_header; /**< PE header */

 typedef struct ne_header {
    uint8_t signature[2]; /**< Magic number NE */
    uint8_t linker_maj_version; /**< Linker major version */
    uint8_t linker_min_version; /**< Linker minor version */
    uint16_t entry_table_offset; /**< Offset of entry table */
    uint16_t entry_table_length; /**< Length of entry table */
    uint32_t fileload_crc; /**< File load CRC */
    uint8_t prog_flags; /**< Program flags */
    uint8_t appl_flags; /**< Application flags */
    uint8_t auto_data_seg_index; /**< Automatic data segment index */
    uint16_t InitHeapSize; /**< Initial local heap size */
    uint16_t InitStackSize; /**< Initial stack size */
    uint32_t EntryPoint; /**< CS:IP entry point, CS is index into segment table */
    uint32_t InitStack; /**< SS:SP inital stack pointer, SS is index into segment table */
    uint16_t num_segs; /**< Number of segments */
    uint16_t num_mod_refs; /**< Number of module references (DLLs) */
    uint16_t nonres_names_tab_size; /**< Size of non-resident names table */
    uint16_t seg_table_offset; /**< Offset of Segment table */
    uint16_t res_table_offset; /**< Offset of resources table */
    uint16_t residnam_table_offset; /**< Offset of resident names table */
    uint16_t modref_table_offset; /**< Offset of module reference table */
    uint16_t importname_table_offset; /**< Offset of imported names table */
    uint32_t nonres_table_offset; /**< Offset from start of file to non-resident names table */
    uint16_t mov_entry_count; /**< Count of movable entry point listed in entry table */
    uint16_t FileAlnSzShftCnt; /**< File alignment size shift count (0=9(default 512 byte pages)) */
    uint16_t num_res_tab_entries; /**< Number of resource table entries */
    uint8_t target_os; /**< Target OS */
    uint8_t os2_exe_flags; /**< Other OS/2 flags */
    uint16_t ret_thunk_offset; /**< Offset to return thunks or start of gangload area */
    uint16_t segrefthunksoff; /**< Offset to segment reference thunks or size of gangload area */
    uint16_t mincodeswap; /**< Minimum code swap area size */
    uint8_t expctwinver[2]; /**< Expected windows version (minor first) */
} ne_header; /**< NE header */

 typedef struct le_header
 {
    uint8_t signature[2]; /**< Magic number LE */
    uint8_t byte_order; /**< Byte order */
    uint8_t word_order; /**< Word order */
    uint32_t exe_format_level;
    uint16_t cpu_type; /**<  */
    uint16_t target_os; /**< Target OS */
    uint32_t module_version;
    uint32_t characteristics; /**< Characteristic flags */
    uint32_t num_pages;
 } le_header; /**< LE header */

typedef struct  elf_header
{
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf_header; /**< ELF header */


typedef struct e32_header
{
    uint32_t uid1;
    uint32_t uid2;
    uint32_t uid3;
    uint32_t uid_checksum;
    uint8_t signature[4];
    uint32_t crc_32;
    uint32_t version;
    uint32_t compression_type;
    uint32_t translator_version;
    uint32_t time_stamp;
    uint8_t flags1;
    uint16_t reserved;
    uint8_t flags2;
} e32_header; /**< E32 header */

const char *exeknow_getfilename(char const *path);
void exeknow_error(int type);
int exeknow_get_filetype(FILE* fp);
void exeknow_get_details_pe(FILE* fp, uint16_t offset);
void exeknow_get_details_ne(FILE* fp, uint16_t offset);
void exeknow_get_details_le(FILE* fp, uint16_t offset);
int exeknow_get_details_mz(FILE* fp);
int exeknow_get_details_elf(FILE* fp);
int exeknow_get_details_e32(FILE* fp);
int exeknow_get_details(FILE* fp, int ftype, const char* fname);
void exeknow_know(const char* fname);
#endif // EXEKNOW_H_INCLUDED
