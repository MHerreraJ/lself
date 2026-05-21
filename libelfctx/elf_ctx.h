/*
 * File:    elf_ctx.h
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

#ifndef ELF_CTX_H
#define ELF_CTX_H

#include <elf.h>
#include <stdio.h>


#define SHT_AT_OFFSET SHT_HIUSER -1


typedef struct{
    FILE* file;
    char* filePath;
    
    Elf64_Ehdr ehdr;

    Elf64_Phdr* phdrs;
    Elf64_Dyn* dyn_entries;
    char* dyn_strtab;
    size_t dyn_strtab_size;

    Elf64_Shdr* shdrs;

    Elf64_Sym* symbols;
    size_t symbols_count;

    Elf64_Sym* dyn_symbols;
    size_t dyn_symbols_count;

    char* symbol_strtab;
    size_t symbol_strtab_size;

    char* dyn_symbol_strtab;
    size_t dyn_symbol_strtab_size;

    int error;
} elf_ctx;






int elf_ctx_ok(elf_ctx* ctx);

int elf_ctx_is_open(elf_ctx* ctx);
elf_ctx elf_ctx_open(const char* filename);

void elf_ctx_close(elf_ctx* ctx);


int elf_ctx_is_type(elf_ctx* ctx, int type, int strictype);
int elf_ctx_is_class(elf_ctx* ctx, int class);
int elf_ctx_is_machine(elf_ctx* ctx, int machine);


// int elf_ctx_get_dyn_entries(elf_ctx* ctx, int tag, elf_dyn*** out, size_t* out_count);
const Elf64_Phdr* elf_ctx_get_program_header(elf_ctx* ctx, Elf64_Word type, unsigned int off);
const Elf64_Dyn* elf_ctx_get_dynamic_section(elf_ctx* ctx);
const Elf64_Dyn* elf_ctx_get_dynamic_section_entry(elf_ctx* ctx, Elf64_Sxword tag, unsigned int off);

const Elf64_Shdr* elf_ctx_get_section_header(elf_ctx* ctx, Elf64_Word type, unsigned int off);
// const elf_ctx_strtab* elf_ctx_get_strtab(elf_ctx* ctx, size_t index);
const Elf64_Sym* elf_ctx_get_symbol(elf_ctx* ctx, size_t index);
const Elf64_Sym* elf_ctx_get_dyn_symbol(elf_ctx* ctx, size_t index);
const char* elf_ctx_get_symbol_name(elf_ctx* ctx, const Elf64_Sym* sym);
const char* elf_ctx_get_dyn_symbol_name(elf_ctx* ctx, const Elf64_Sym* sym);


const char* elf_ctx_get_dynamic_section_strtab(elf_ctx* ctx);
const char* elf_ctx_get_dynamic_entry_str(elf_ctx* ctx, const Elf64_Dyn* entry);

int elf_ctx_get_error(elf_ctx* ctx);


int elf_str_parse_machine_name(const char* str);
int elf_strn_parse_machine_name(const char* str, size_t len);
const char* elf_machine_name(Elf64_Half machine);


int elf_strn_parse_type_name(const char* str, size_t len);
int elf_str_parse_type_name(const char* str);
const char* elf_type_name(Elf64_Half type);


const char* elf_class_name(int class);

#endif // ELF_CTX_H
