/*
 * File:    elf_ctx.c
 * Author:  Manuel Herrera Juarez
 * Date:    2026-03-24
 * License: GNU Lesser General Public License v3.0 (LGPLv3)
 *
 * This file is part of a free software library: you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <errno.h>
#include <elf.h>
#include <ctype.h>
#include <strings.h>
#include <stdlib.h>
#include "elf_ctx.h"

#ifndef EM_ARCV2
#define EM_ARCV2 195
#endif

#ifndef EM_INTELGT
#define EM_INTELGT 205
#endif

#ifndef EM_CSKY
#define EM_CSKY 252
#endif

#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif


static void __ehdr32_to_ehdr64(Elf32_Ehdr* ehdr32, Elf64_Ehdr* ehdr64) {
    memset(ehdr64, 0, sizeof(Elf64_Ehdr));
    memcpy(ehdr64->e_ident, ehdr32->e_ident, EI_NIDENT);

    ehdr64->e_type      = (Elf64_Half)ehdr32->e_type;
    ehdr64->e_machine   = (Elf64_Half)ehdr32->e_machine;
    ehdr64->e_version   = (Elf64_Word)ehdr32->e_version;
    ehdr64->e_entry     = (Elf64_Addr)ehdr32->e_entry;
    ehdr64->e_phoff     = (Elf64_Off) ehdr32->e_phoff;
    ehdr64->e_shoff     = (Elf64_Off) ehdr32->e_shoff;
    ehdr64->e_flags     = (Elf64_Word)ehdr32->e_flags;
    ehdr64->e_ehsize    = (Elf64_Half)ehdr32->e_ehsize;
    ehdr64->e_phentsize = (Elf64_Half)ehdr32->e_phentsize;
    ehdr64->e_phnum     = (Elf64_Half)ehdr32->e_phnum;
    ehdr64->e_shentsize = (Elf64_Half)ehdr32->e_shentsize;
    ehdr64->e_shnum     = (Elf64_Half)ehdr32->e_shnum;
    ehdr64->e_shstrndx  = (Elf64_Half)ehdr32->e_shstrndx;
}

static void __phdr32_to_phdr64(Elf32_Phdr* phdr32, Elf64_Phdr* phdr64) {
    memset(phdr64, 0, sizeof(Elf64_Phdr));

    phdr64->p_type   = (Elf64_Word)phdr32->p_type;
    phdr64->p_flags  = (Elf64_Word)phdr32->p_flags;
    phdr64->p_offset = (Elf64_Off) phdr32->p_offset;
    phdr64->p_vaddr  = (Elf64_Addr)phdr32->p_vaddr;
    phdr64->p_paddr  = (Elf64_Addr)phdr32->p_paddr;
    phdr64->p_filesz = (Elf64_Xword)phdr32->p_filesz;
    phdr64->p_memsz  = (Elf64_Xword)phdr32->p_memsz;
    phdr64->p_align  = (Elf64_Xword)phdr32->p_align;
}

static void __dyn32_to_dyn64(Elf32_Dyn* dyn32, Elf64_Dyn* dyn64) {
    memset(dyn64, 0, sizeof(Elf64_Dyn));

    dyn64->d_tag = (Elf64_Sxword)dyn32->d_tag;
    dyn64->d_un.d_val = (Elf64_Xword)dyn32->d_un.d_val;
    dyn64->d_un.d_ptr = (Elf64_Addr)dyn32->d_un.d_ptr;
}

int elf_ctx_ok(elf_ctx* ctx) {
    if(!ctx || !ctx->file || ctx->error != 0) {
        return 0;
    }
    return 1;
}

int elf_ctx_is_open(elf_ctx* ctx){
    if(!ctx) {
        return 0;
    }
    return ctx->file != NULL;
}


elf_ctx elf_ctx_open(const char* filename) {
    elf_ctx ctx = {0};

    FILE* file = NULL;
    char ident[EI_NIDENT];
    memset(ident, 0, EI_NIDENT);

    if(!filename || filename[0] == '\0') {
        ctx.error = EINVAL;
        return ctx;
    }

    file = fopen(filename, "rb");
    if (!file) {
        ctx.error = ENOENT;
        return ctx;
    }

    if (fread(ident, 1, EI_NIDENT, file) != EI_NIDENT) {
        fclose(file);
        ctx.error = EIO;
        return ctx;
    }

    // Check ELF magic number
    if(memcmp(ident, ELFMAG, SELFMAG) != 0) {
        fclose(file);
        ctx.error = EINVAL;
        return ctx;
    }
    fseek(file, 0, SEEK_SET);

    // Check class
    if(ident[EI_CLASS] != ELFCLASS32 && ident[EI_CLASS] != ELFCLASS64) {
        fclose(file);
        ctx.error = EINVAL;
        return ctx;
    }

    // Check data encoding
    if(ident[EI_DATA] != ELFDATA2LSB && ident[EI_DATA] != ELFDATA2MSB) {
        fclose(file);
        ctx.error = EINVAL;
        return ctx;
    }

    // Check version
    if(ident[EI_VERSION] != EV_CURRENT) {
        fclose(file);
        ctx.error = EINVAL;
        return ctx;
    }

    // Check OS ABI (only support SYSV and LINUX for now)
    if(ident[EI_OSABI] != ELFOSABI_SYSV && ident[EI_OSABI] != ELFOSABI_LINUX) {
        fclose(file);
        ctx.error = EINVAL;
        return ctx;
    }

    // Now read the rest of the header based on class
    if(ident[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr ehdr32 = {0};
        if (fread(&ehdr32, 1, sizeof(Elf32_Ehdr), file) != sizeof(Elf32_Ehdr)) {
            fclose(file);
            ctx.error = EIO;
            return ctx;
        }
        __ehdr32_to_ehdr64(&ehdr32, &ctx.ehdr);
    } else{
        if (fread(&ctx.ehdr, 1, sizeof(Elf64_Ehdr), file) != sizeof(Elf64_Ehdr)) {
            fclose(file);
            ctx.error = EIO;
            return ctx;
        }
    }

    ctx.file = file;
    ctx.error = 0;

    return ctx;
}


void elf_ctx_close(elf_ctx* ctx) {
    if(!ctx) return;
    if(ctx->file){
        fclose(ctx->file);
        ctx->file = NULL;
    }
    if(ctx->filePath){
        free(ctx->filePath);
        ctx->filePath = NULL;
    }
    if(ctx->phdrs){
        free(ctx->phdrs);
        ctx->phdrs = NULL;
    }
    if( ctx->dyn_entries){
        free(ctx->dyn_entries);
        ctx->dyn_entries = NULL;
    }
    if(ctx->strtab){
        free(ctx->strtab);
        ctx->strtab = NULL;
    }
    ctx->strtab_size = 0;
}

int elf_ctx_get_error(elf_ctx* ctx) {
    if(!ctx) {
        return EINVAL;
    }
    if(ctx->error == 0 && !ctx->file) {
        return EINVAL;
    }
    return ctx->error;
}

static int elf_ctx_is_exec(elf_ctx* ctx)
{
    if(ctx->ehdr.e_type == ET_EXEC){
        return 1;
    }

    // Shared objects can also be executable
    if(ctx->ehdr.e_type != ET_DYN){
        return 0;
    }
    // Check if it has an executable segment
    const Elf64_Phdr* phdr = elf_ctx_get_program_header(ctx, PT_INTERP, 0);
    if(phdr){
        return 1;
    }

    // Some PIE executables might not have an INTERP segment, but they will have a LOAD segment with execute permissions
    phdr = elf_ctx_get_program_header(ctx, PT_LOAD, 0);
    if(phdr && (phdr->p_flags & PF_X)){
        return 1;
    }
    return 0;
}

int elf_ctx_is_type(elf_ctx* ctx, int type, int strictype)
{
    int isExec = 0;
    if(!elf_ctx_ok(ctx)) {
        return 0;
    }
    if(!strictype){
        if(type == ET_EXEC){
            isExec = elf_ctx_is_exec(ctx);
            return isExec;
        }else if(type == ET_DYN){
            isExec = elf_ctx_is_exec(ctx);
            if(isExec){
                return 0;
            }
        }
    }
    return ctx->ehdr.e_type == type;
}

int elf_ctx_is_class(elf_ctx* ctx, int class)
{
    if(!elf_ctx_ok(ctx)) {
        return 0;
    }
    return ctx->ehdr.e_ident[EI_CLASS] == class;
}

int elf_ctx_is_machine(elf_ctx* ctx, int machine)
{
    if(!elf_ctx_ok(ctx)) {
        return 0;
    }
    return ctx->ehdr.e_machine == machine;
}

static int elf_ctx_get_program_header_table(elf_ctx* ctx)
{
    if(!elf_ctx_ok(ctx)) {
        return EINVAL;
    }
    if(ctx->phdrs) {
        // Already read
        return 0;
    }

    int is32bit = ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS32;

    // Move cursor to program header table
    if(fseek(ctx->file, ctx->ehdr.e_phoff, SEEK_SET) != 0) {
        // Set errror 
        return EIO;
    }

    //Allocate memory for program headers
    ctx->phdrs = (Elf64_Phdr*)calloc(ctx->ehdr.e_phnum + 1, sizeof(Elf64_Phdr));
    if(!ctx->phdrs) {
        return ENOMEM;
    }

    // Read program headers
    size_t i = 0;
    for(i = 0; i < ctx->ehdr.e_phnum; i++) {
        if(is32bit){
            Elf32_Phdr phdr32;
            if (fread(&phdr32, 1, sizeof(Elf32_Phdr), ctx->file) != sizeof(Elf32_Phdr)) {
                free(ctx->phdrs);
                ctx->phdrs = NULL;
                return EIO;
            }
            __phdr32_to_phdr64(&phdr32, &ctx->phdrs[i]);
        }else{
            if (fread(&ctx->phdrs[i], 1, sizeof(Elf64_Phdr), ctx->file) != sizeof(Elf64_Phdr)) {
                free(ctx->phdrs);
                ctx->phdrs = NULL;
                return EIO;
            }
        }
    }

    // Add null terminator for easier iteration
    ctx->phdrs[i].p_type = PT_NULL;
    return 0;
}

const Elf64_Phdr* elf_ctx_get_program_header(elf_ctx* ctx, Elf64_Word type, unsigned int off)
{
    if(!elf_ctx_ok(ctx)) {
        return NULL;
    }

    if(type <= 0) {
        return NULL;
    }

    if(!ctx->phdrs){
        int ret = elf_ctx_get_program_header_table(ctx);
        if(ret != 0){
            return NULL;
        }
    }

    Elf64_Phdr* phdr = ctx->phdrs;
    while(phdr->p_type != PT_NULL) {
        if(phdr->p_type == type) {
            if(off == 0) {
                return phdr;
            }
            off--;
        }
        phdr++;
    }

    return NULL;
}

const Elf64_Dyn* elf_ctx_get_dynamic_section(elf_ctx* ctx)
{
    if(!elf_ctx_ok(ctx)) {
        return NULL;
    }
    if(ctx->dyn_entries) {
        return ctx->dyn_entries;
    }

    Elf64_Dyn* dynEntries = NULL;
    size_t dynEntryCount = 0;
    size_t maxDynEntries = 0;

    const Elf64_Phdr* dynPhdr = NULL;
    int is32bit = ctx->ehdr.e_ident[EI_CLASS] == ELFCLASS32;

    dynPhdr = elf_ctx_get_program_header(ctx, PT_DYNAMIC, 0);
    if(!dynPhdr){
        return NULL;
    }

    if(dynPhdr->p_filesz == 0){
        return NULL;
    }

    maxDynEntries = dynPhdr->p_filesz / (is32bit ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn));
    dynEntries = (Elf64_Dyn*)calloc(maxDynEntries+1, sizeof(Elf64_Dyn));
    if(!dynEntries) {
        return NULL;
    }

    //Now read the dynamic section entries
    // Move cursor to dynamic section
    if(fseek(ctx->file, dynPhdr->p_offset, SEEK_SET) != 0) {
        free(dynEntries);
        return NULL;
    }

    Elf64_Dyn* entry = NULL;
    // Read entries until we find a DT_NULL or reach max entries
    do{
        entry = &dynEntries[dynEntryCount++];
        if(is32bit){
            Elf32_Dyn dyn32;
            if (fread(&dyn32, 1, sizeof(Elf32_Dyn), ctx->file) != sizeof(Elf32_Dyn)) {
                free(dynEntries);
                return NULL;
            }
            __dyn32_to_dyn64(&dyn32, entry);
        }else{
            if (fread(entry, 1, sizeof(Elf64_Dyn), ctx->file) != sizeof(Elf64_Dyn)) {
                free(dynEntries);
                return NULL;
            }
        }
    }while(entry->d_tag != DT_NULL  && dynEntryCount < maxDynEntries);
    if(entry->d_tag != DT_NULL){
        //Add a null terminator if we reached max entries without finding one
        entry=&dynEntries[dynEntryCount];
        memset(entry, 0, sizeof(Elf64_Dyn));
        entry->d_tag = DT_NULL;
    }

    ctx->dyn_entries = dynEntries;
    return ctx->dyn_entries;
}

const Elf64_Dyn* elf_ctx_get_dynamic_section_entry(elf_ctx* ctx, Elf64_Sxword tag, unsigned int off)
{
    if(!elf_ctx_ok(ctx)) {
        return NULL;
    }

    const Elf64_Dyn* dyn = elf_ctx_get_dynamic_section(ctx);
    if(!dyn) {
        return NULL;
    }

    while(dyn->d_tag != DT_NULL) {
        if(dyn->d_tag == tag) {
            if(off == 0) {
                return dyn;
            }
            off--;
        }
        dyn++;
    }

    return NULL;
}

const char* elf_ctx_get_dynamic_section_strtab(elf_ctx* ctx)
{
    if(!elf_ctx_ok(ctx)) {
        return NULL;
    }

    if(ctx->strtab) {
        return ctx->strtab;
    }


    const Elf64_Dyn* strtabEntry = elf_ctx_get_dynamic_section_entry(ctx, DT_STRTAB, 0);
    const Elf64_Dyn* strtabSizeEntry = elf_ctx_get_dynamic_section_entry(ctx, DT_STRSZ, 0);

    if(!strtabEntry || !strtabSizeEntry) {
        return NULL;
    }

    if(strtabEntry->d_un.d_ptr == 0 || strtabSizeEntry->d_un.d_val == 0) {
        return NULL;
    }
    
    // We need to find which segment contains the string table to get the file offset
    const Elf64_Phdr* loadSegment = NULL;
    unsigned int offset = 0;
    do{
        loadSegment = elf_ctx_get_program_header(ctx, PT_LOAD, offset++);
        if(!loadSegment){
            return NULL;
        }

        if(strtabEntry->d_un.d_ptr >= (loadSegment->p_vaddr & -loadSegment->p_align) &&
            (strtabEntry->d_un.d_ptr + strtabSizeEntry->d_un.d_val) <= (loadSegment->p_vaddr + loadSegment->p_filesz)){
            break;
        }
    }while(loadSegment);

    // Calculate file offset of string table
    uint64_t strTblOffset = 0;
    strTblOffset = strtabEntry->d_un.d_ptr - loadSegment->p_vaddr + loadSegment->p_offset;
    if(strTblOffset == 0){
        return NULL;
    }

    // Move cursor to string table and read it
    if(fseek(ctx->file, strTblOffset, SEEK_SET) != 0) {
        return NULL;
    }

    char* strtab = (char*)malloc(strtabSizeEntry->d_un.d_val);
    if(!strtab) {
        return NULL;
    }

    if(fread(strtab, 1, strtabSizeEntry->d_un.d_val, ctx->file) != strtabSizeEntry->d_un.d_val) {
        free(strtab);
        return NULL;
    }

    ctx->strtab = strtab;
    ctx->strtab_size = strtabSizeEntry->d_un.d_val;
    return ctx->strtab;
}


const char* elf_ctx_get_dynamic_entry_str(elf_ctx* ctx, const Elf64_Dyn* entry)
{
    if(!elf_ctx_ok(ctx) || !entry) {
        return NULL;
    }

    const char* strtab = elf_ctx_get_dynamic_section_strtab(ctx);
    if(!strtab) {
        return NULL;
    }

    if(entry->d_un.d_val >= ctx->strtab_size) {
        return NULL;
    }

    return &strtab[entry->d_un.d_val];
}

#define MAX_MACHINE_NAME_LEN 32
#define STR_EQUAL(s1, cs2, l) ( ( (sizeof(cs2)-1)==l) && (strncasecmp(s1, cs2, l) == 0))

int elf_strn_parse_machine_name(const char* str, size_t len)
{
    if(!str || str[0] == '\0' || len == 0) return EM_NONE;
    if(len == (size_t)-1) {
        len = strnlen(str, MAX_MACHINE_NAME_LEN+1);
    }
    if(len > MAX_MACHINE_NAME_LEN) return EM_NONE;


    if(STR_EQUAL(str, "none", len)) return EM_NONE;
    if(STR_EQUAL(str, "m32", len)) return EM_M32;
    if(STR_EQUAL(str, "sparc", len)) return EM_SPARC;
    if(STR_EQUAL(str, "i386", len)) return EM_386;
    if(STR_EQUAL(str, "x86", len)) return EM_386;
    if(STR_EQUAL(str, "m68k", len)) return EM_68K;
    if(STR_EQUAL(str, "m88k", len)) return EM_88K;
    if(STR_EQUAL(str, "intel mcu", len)) return EM_IAMCU;
    if(STR_EQUAL(str, "i860", len)) return EM_860;
    if(STR_EQUAL(str, "mips", len)) return EM_MIPS;
    if(STR_EQUAL(str, "s/370", len)) return EM_S370;
    if(STR_EQUAL(str, "mips le", len)) return EM_MIPS_RS3_LE;
    if(STR_EQUAL(str, "pa-risc", len)) return EM_PARISC;
    if(STR_EQUAL(str, "vpp500", len)) return EM_VPP500;
    if(STR_EQUAL(str, "sparc32+", len)) return EM_SPARC32PLUS;
    if(STR_EQUAL(str, "i960", len)) return EM_960;
    if(STR_EQUAL(str, "powerpc", len)) return EM_PPC;
    if(STR_EQUAL(str, "powerpc64", len)) return EM_PPC64;
    if(STR_EQUAL(str, "s390x", len)) return EM_S390;
    if(STR_EQUAL(str, "spu", len)) return EM_SPU;
    if(STR_EQUAL(str, "v800", len)) return EM_V800;
    if(STR_EQUAL(str, "fr20", len)) return EM_FR20;
    if(STR_EQUAL(str, "rh32", len)) return EM_RH32;
    if(STR_EQUAL(str, "rce", len)) return EM_RCE; 
    if(STR_EQUAL(str, "arm", len)) return EM_ARM;
    if(STR_EQUAL(str, "arm32", len)) return EM_ARM;
    if(STR_EQUAL(str, "alpha", len)) return EM_FAKE_ALPHA;
    if(STR_EQUAL(str, "superh", len)) return EM_SH;
    if(STR_EQUAL(str, "sparc v9", len)) return EM_SPARCV9;
    if(STR_EQUAL(str, "tricore", len)) return EM_TRICORE;
    if(STR_EQUAL(str, "arc", len)) return EM_ARC;
    if(STR_EQUAL(str, "h8/300", len)) return EM_H8_300;
    if(STR_EQUAL(str, "h8/300h", len)) return EM_H8_300H;
    if(STR_EQUAL(str, "h8s", len)) return EM_H8S;
    if(STR_EQUAL(str, "h8/500", len)) return EM_H8_500;
    if(STR_EQUAL(str, "itanium", len)) return EM_IA_64;
    if(STR_EQUAL(str, "mips x", len)) return EM_MIPS_X;
    if(STR_EQUAL(str, "coldfire", len)) return EM_COLDFIRE;
    if(STR_EQUAL(str, "68hc12", len)) return EM_68HC12;
    if(STR_EQUAL(str, "mma", len)) return EM_MMA;
    if(STR_EQUAL(str, "pcp", len)) return EM_PCP;
    if(STR_EQUAL(str, "ncpu", len)) return EM_NCPU;
    if(STR_EQUAL(str, "ndr1", len)) return EM_NDR1;
    if(STR_EQUAL(str, "starcore", len)) return EM_STARCORE;
    if(STR_EQUAL(str, "me16", len)) return EM_ME16;
    if(STR_EQUAL(str, "st100", len)) return EM_ST100;
    if(STR_EQUAL(str, "tinyj", len)) return EM_TINYJ;
    if(STR_EQUAL(str, "x86-64", len)) return EM_X86_64;
    if(STR_EQUAL(str, "x86_64", len)) return EM_X86_64;
    if(STR_EQUAL(str, "amd64", len)) return EM_X86_64;
    if(STR_EQUAL(str, "pdsp", len)) return EM_PDSP;
    if(STR_EQUAL(str, "pdp-10", len)) return EM_PDP10;
    if(STR_EQUAL(str, "pdp-11", len)) return EM_PDP11;
    if(STR_EQUAL(str, "fx66", len)) return EM_FX66;
    if(STR_EQUAL(str, "st9+", len)) return EM_ST9PLUS;
    if(STR_EQUAL(str, "st7", len)) return EM_ST7;
    if(STR_EQUAL(str, "68hc16", len)) return EM_68HC16;
    if(STR_EQUAL(str, "68hc11", len)) return EM_68HC11;
    if(STR_EQUAL(str, "68hc08", len)) return EM_68HC08;
    if(STR_EQUAL(str, "68hc05", len)) return EM_68HC05;
    if(STR_EQUAL(str, "svx", len)) return EM_SVX;
    if(STR_EQUAL(str, "st19", len)) return EM_ST19;
    if(STR_EQUAL(str, "vax", len)) return EM_VAX;
    if(STR_EQUAL(str, "cris", len)) return EM_CRIS;
    if(STR_EQUAL(str, "javelin", len)) return EM_JAVELIN;
    if(STR_EQUAL(str, "firepath", len)) return EM_FIREPATH;
    if(STR_EQUAL(str, "zsp", len)) return EM_ZSP;
    if(STR_EQUAL(str, "mmix", len)) return EM_MMIX;
    if(STR_EQUAL(str, "huany", len)) return EM_HUANY;
    if(STR_EQUAL(str, "prism", len)) return EM_PRISM;
    if(STR_EQUAL(str, "avr", len)) return EM_AVR;
    if(STR_EQUAL(str, "fr30", len)) return EM_FR30;
    if(STR_EQUAL(str, "d10v", len)) return EM_D10V;
    if(STR_EQUAL(str, "d30v", len)) return EM_D30V;
    if(STR_EQUAL(str, "v850", len)) return EM_V850;
    if(STR_EQUAL(str, "m32r", len)) return EM_M32R;
    if(STR_EQUAL(str, "mn10300", len)) return EM_MN10300;
    if(STR_EQUAL(str, "mn10200", len)) return EM_MN10200;
    if(STR_EQUAL(str, "picojava", len)) return EM_PJ;
    if(STR_EQUAL(str, "openrisc", len)) return EM_OPENRISC;
    if(STR_EQUAL(str, "arc compact", len)) return EM_ARC_COMPACT;
    if(STR_EQUAL(str, "xtensa", len)) return EM_XTENSA;
    if(STR_EQUAL(str, "videocore", len)) return EM_VIDEOCORE;
    if(STR_EQUAL(str, "tmm gpp", len)) return EM_TMM_GPP;
    if(STR_EQUAL(str, "ns32k", len)) return EM_NS32K;
    if(STR_EQUAL(str, "tpc", len)) return EM_TPC;
    if(STR_EQUAL(str, "snp1k", len)) return EM_SNP1K;
    if(STR_EQUAL(str, "st200", len)) return EM_ST200;
    if(STR_EQUAL(str, "ip2k", len)) return EM_IP2K;
    if(STR_EQUAL(str, "max", len)) return EM_MAX;
    if(STR_EQUAL(str, "cr", len)) return EM_CR;
    if(STR_EQUAL(str, "f2mc16", len)) return EM_F2MC16;
    if(STR_EQUAL(str, "msp430", len)) return EM_MSP430;
    if(STR_EQUAL(str, "blackfin", len)) return EM_BLACKFIN;

    if(STR_EQUAL(str, "aarch64", len)) return EM_AARCH64;
    if(STR_EQUAL(str, "arm64", len)) return EM_AARCH64;
    if(STR_EQUAL(str, "riscv", len)) return EM_RISCV;
    

    return EM_NONE;
}


int elf_str_parse_machine_name(const char* str)
{
    return elf_strn_parse_machine_name(str, (size_t)-1);
}

const char* elf_machine_name(Elf64_Half machine)
{
    switch (machine)
    {
		case EM_NONE: return "none";
		case EM_M32: return "m32";
		case EM_SPARC: return "sparc";
		case EM_386: return "i386";
		case EM_68K: return "m68k";
		case EM_88K: return "m88k";
		case EM_IAMCU: return "intel mcu";
		case EM_860: return "i860";
		case EM_MIPS: return "mips";
		case EM_S370: return "s/370";
		case EM_MIPS_RS3_LE: return "mips le";
		case EM_PARISC: return "pa-risc";
		case EM_VPP500: return "vpp500";
		case EM_SPARC32PLUS: return "sparc32+";
		case EM_960: return "i960";
		case EM_PPC: return "powerpc";
		case EM_PPC64: return "powerpc64";
		case EM_S390: return "s390x";
		case EM_SPU: return "spu";
		case EM_V800: return "v800";
		case EM_FR20: return "fr20";
		case EM_RH32: return "rh32";
		case EM_RCE: return "rce";
		case EM_ARM: return "arm";
		case EM_FAKE_ALPHA: return "alpha";
		case EM_SH: return "superh";
		case EM_SPARCV9: return "sparc v9";
		case EM_TRICORE: return "tricore";
		case EM_ARC: return "arc";
		case EM_H8_300: return "h8/300";
		case EM_H8_300H: return "h8/300h";
		case EM_H8S: return "h8s";
		case EM_H8_500: return "h8/500";
		case EM_IA_64: return "itanium";
		case EM_MIPS_X: return "mips x";
		case EM_COLDFIRE: return "coldfire";
		case EM_68HC12: return "68hc12";
		case EM_MMA: return "mma";
		case EM_PCP: return "pcp";
		case EM_NCPU: return "ncpu";
		case EM_NDR1: return "ndr1";
		case EM_STARCORE: return "starcore";
		case EM_ME16: return "me16";
		case EM_ST100: return "st100";
		case EM_TINYJ: return "tinyj";
		case EM_X86_64: return "x86-64";
		case EM_PDSP: return "pdsp";
		case EM_PDP10: return "pdp-10";
		case EM_PDP11: return "pdp-11";
		case EM_FX66: return "fx66";
		case EM_ST9PLUS: return "st9+";
		case EM_ST7: return "st7";
		case EM_68HC16: return "68hc16";
		case EM_68HC11: return "68hc11";
		case EM_68HC08: return "68hc08";
		case EM_68HC05: return "68hc05";
		case EM_SVX: return "svx";
		case EM_ST19: return "st19";
		case EM_VAX: return "vax";
		case EM_CRIS: return "cris";
		case EM_JAVELIN: return "javelin";
		case EM_FIREPATH: return "firepath";
		case EM_ZSP: return "zsp";
		case EM_MMIX: return "mmix";
		case EM_HUANY: return "huany";
		case EM_PRISM: return "prism";
		case EM_AVR: return "avr";
		case EM_FR30: return "fr30";
		case EM_D10V: return "d10v";
		case EM_D30V: return "d30v";
		case EM_V850: return "v850";
		case EM_M32R: return "m32r";
		case EM_MN10300: return "mn10300";
		case EM_MN10200: return "mn10200";
		case EM_PJ: return "picojava";
		case EM_OPENRISC: return "openrisc";
		case EM_ARC_COMPACT: return "arc compact";
		case EM_XTENSA: return "xtensa";
		case EM_VIDEOCORE: return "videocore";
		case EM_TMM_GPP: return "tmm gpp";
		case EM_NS32K: return "ns32k";
		case EM_TPC: return "tpc";
		case EM_SNP1K: return "snp1k";
		case EM_ST200: return "st200";
		case EM_IP2K: return "ip2k";
		case EM_MAX: return "max";
		case EM_CR: return "cr";
		case EM_F2MC16: return "f2mc16";
		case EM_MSP430: return "msp430";
		case EM_BLACKFIN: return "blackfin";
		case EM_SE_C33: return "c33";
		case EM_SEP: return "sep";
		case EM_ARCA: return "arca";
		case EM_UNICORE: return "unicore";
		case EM_EXCESS: return "excess";
		case EM_DXP: return "dxp";
		case EM_ALTERA_NIOS2: return "nios2";
		case EM_CRX: return "crx";
		case EM_XGATE: return "xgate";
		case EM_C166: return "c166";
		case EM_M16C: return "m16c";
		case EM_DSPIC30F: return "dspic30f";
		case EM_CE: return "ce";
		case EM_M32C: return "m32c";
		case EM_TSK3000: return "tsk3000";
		case EM_RS08: return "rs08";
		case EM_SHARC: return "sharc";
		case EM_ECOG2: return "ecog2";
		case EM_SCORE7: return "score7";
		case EM_DSP24: return "dsp24";
		case EM_VIDEOCORE3: return "videocore3";
		case EM_LATTICEMICO32: return "lm32";
		case EM_SE_C17: return "c17";
		case EM_TI_C6000: return "tms320c6000";
		case EM_TI_C2000: return "tms320c2000";
		case EM_TI_C5500: return "tms320c55x";
		case EM_TI_ARP32: return "ti arp32";
		case EM_TI_PRU: return "ti pru";
		case EM_MMDSP_PLUS: return "mmdsp+";
		case EM_CYPRESS_M8C: return "cypress m8c";
		case EM_R32C: return "r32c";
		case EM_TRIMEDIA: return "trimedia";
		case EM_QDSP6: return "qdsp6";
		case EM_8051: return "8051";
		case EM_STXP7X: return "stxp7x";
		case EM_NDS32: return "nds32";
		case EM_ECOG1X: return "ecog1x";
		case EM_MAXQ30: return "maxq30";
		case EM_XIMO16: return "ximo16";
		case EM_MANIK: return "manik";
		case EM_CRAYNV2: return "cray nv2";
		case EM_RX: return "rx";
		case EM_METAG: return "meta";
		case EM_MCST_ELBRUS: return "elbrus";
		case EM_ECOG16: return "ecog16";
		case EM_CR16: return "cr-16";
		case EM_ETPU: return "etpu";
		case EM_SLE9X: return "sle9x";
		case EM_L10M: return "l10m";
		case EM_K10M: return "k10m";
		case EM_AARCH64: return "aarch64";
		case EM_AVR32: return "avr32";
		case EM_STM8: return "stm8";
		case EM_TILE64: return "tile64";
		case EM_TILEPRO: return "tilepro";
		case EM_MICROBLAZE: return "microblaze";
		case EM_CUDA: return "cuda";
		case EM_TILEGX: return "tile-gx";
		case EM_CLOUDSHIELD: return "cloudshield";
		case EM_COREA_1ST: return "core a1st";
		case EM_COREA_2ND: return "core a2nd";
		case EM_ARCV2: return "arc v2";
		case EM_OPEN8: return "open8";
		case EM_RL78: return "rl78";
		case EM_VIDEOCORE5: return "videocore5";
		case EM_78KOR: return "78kor";
		case EM_56800EX: return "56800ex";
		case EM_BA1: return "ba1";
		case EM_BA2: return "ba2";
		case EM_XCORE: return "xcore";
		case EM_MCHP_PIC: return "pic";
		case EM_INTELGT: return "intel gpu";
		case EM_KM32: return "km32";
		case EM_KMX32: return "kmx32";
		case EM_EMX16: return "emx16";
		case EM_EMX8: return "emx8";
		case EM_KVARC: return "kvarc";
		case EM_CDP: return "cdp";
		case EM_COGE: return "coge";
		case EM_COOL: return "cool";
		case EM_NORC: return "norc";
		case EM_CSR_KALIMBA: return "kalimba";
		case EM_Z80: return "z80";
		case EM_VISIUM: return "visium";
		case EM_FT32: return "ft32";
		case EM_MOXIE: return "moxie";
		case EM_AMDGPU: return "amd gpu";
		case EM_RISCV: return "riscv";
		case EM_BPF: return "ebpf";
		case EM_CSKY: return "c-sky";
		case EM_LOONGARCH: return "loongarch";
		default: return "unknown";
	}
}

#define MAX_TYPE_NAME_LEN 16
int elf_strn_parse_type_name(const char* str, size_t len)
{
    if(!str || str[0] == '\0' || len == 0) return ET_NONE;
    if(len == (size_t)-1) {
        len = strnlen(str, MAX_TYPE_NAME_LEN+1);
    }
    if(len > MAX_TYPE_NAME_LEN) return ET_NONE;

    if(STR_EQUAL(str, "relocatable", len)) return ET_REL;
    if(STR_EQUAL(str, "rel", len)) return ET_REL;
    if(STR_EQUAL(str, "r", len)) return ET_REL;

    if(STR_EQUAL(str, "executable", len)) return ET_EXEC;
    if(STR_EQUAL(str, "exec", len)) return ET_EXEC;
    if(STR_EQUAL(str, "e", len)) return ET_EXEC;

    if(STR_EQUAL(str, "shared", len)) return ET_DYN;
    if(STR_EQUAL(str, "s", len)) return ET_DYN;

    if(STR_EQUAL(str, "dynamic", len)) return ET_DYN;
    if(STR_EQUAL(str, "dyn", len)) return ET_DYN;
    if(STR_EQUAL(str, "d", len)) return ET_DYN;

    if(STR_EQUAL(str, "core", len)) return ET_CORE;
    if(STR_EQUAL(str, "c", len)) return ET_CORE;

    return ET_NONE;
}

int elf_str_parse_type_name(const char* str)
{
    return elf_strn_parse_type_name(str, (size_t)-1);
}

const char* elf_type_name(Elf64_Half type)
{
    switch (type)
    {
        case ET_NONE: return "none";
        case ET_REL: return "rel";
        case ET_EXEC: return "exec";
        case ET_DYN: return "shared";
        case ET_CORE: return "core";
        default: return "unknown";
    }
}


const char* elf_class_name(int class)
{
    switch (class)
    {
        case ELFCLASSNONE: return "none";
        case ELFCLASS32: return "32-bit";
        case ELFCLASS64: return "64-bit";
        default: return "unknown";
    }
}
