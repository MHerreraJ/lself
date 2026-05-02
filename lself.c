/*
 * File:    lself.c
 * Project: lself
 * Author:  Manuel Herrera Juarez
 * Date:    2026-03-24
 * License: GNU General Public License v3.0 (GPLv3)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <sys/stat.h>

#include <fts.h>
#include <unistd.h>

#include <elf.h>

#include "utils.h"
#include "elf_ctx.h"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PROGRAM_VERSION "1.0.0"

DECLARE_DYNARR(char*, str_array, free, ,strdup)
DECLARE_DYNARR(int, int_array, (void), ,(int))

DECLARE_DYNARR_NOCOPY(elf_ctx, elf_ctx_array, elf_ctx_close, &)


typedef struct{
    char* name;
    int type; // If type<0, match any type
}elf_symbol;

void elf_symbol_deinit(elf_symbol* sym)
{
    if(sym->name){
        free(sym->name);
        sym->name = NULL;
    }
    sym->type = 0;
}

DECLARE_DYNARR(elf_symbol, elf_symbol_array, elf_symbol_deinit, & ,)

typedef struct{
    str_array input_paths;
    str_array ignore_patterns;
    str_array ignore_extension_patterns;
    int_array filter_archs;
    int_array filter_types;
    str_array filter_libs;
    elf_symbol_array filter_symbols;

    int testMode;
    int verbose;
    
    int recursive;
    int depth;

    int asList;
    int prettyFormat;
    int printFullPath;
    int printRealPath;
    int printOnePerLine;
    int colorize;
    
    int showArch;
    int showType;
    int showLibs;
    int showSymbols;

    int processedPathCount;

    // If true, only match the exact type. 
    //If false, treat ET_EXEC as matching both ET_EXEC and ET_DYN, 
    // and treat ET_DYN as matching both ET_DYN and ET_EXEC.
    int strictType; 
}lsdelf_ctx;

void lsdelf_ctx_init(lsdelf_ctx* ctx){
    memset(ctx, 0, sizeof(lsdelf_ctx));
    ctx->depth = 1;// Default depth is 1 (non-recursive)
    ctx->colorize = 1; // Default colorize is on
    ctx->showArch = 1; // Show architecture by default
    ctx->showType = 1; // Show type by default
    ctx->showLibs = 1; // Show linked libraries by default
}

void lsdelf_ctx_free(lsdelf_ctx* ctx)
{
    if(!ctx) return;
    release_str_array(&ctx->input_paths);
    release_str_array(&ctx->ignore_patterns);
    release_str_array(&ctx->ignore_extension_patterns);
    release_int_array(&ctx->filter_archs);
    release_int_array(&ctx->filter_types);
    release_str_array(&ctx->filter_libs);
    release_elf_symbol_array(&ctx->filter_symbols);
}

// Helper function to extract filename from a path
const char* get_filename(const char* path)
{
    const char* lastSlash = strrchr(path, '/');
    if(lastSlash){
        return lastSlash + 1;
    }
    return path;
}

// Simple wildcard matching function supporting '*'
int str_wildcard_match(const char* pattern, const char* str)
{
    while(*pattern && *str){
        if(*pattern == '*'){
            // Skip consecutive '*'
            while(*pattern == '*') pattern++;
            if(!*pattern) return 1; // Trailing '*' matches everything
            while(*str){
                if(str_wildcard_match(pattern, str)){
                    return 1;
                }
                str++;
            }
            return 0; // No match found
        }else if(*pattern == *str){
            pattern++;
            str++;
        }else{
            return 0; // Mismatch
        }
    }

    // Skip trailing '*' in pattern
    while(*pattern == '*') pattern++;

    return *pattern == '\0' && *str == '\0';
}

int is_path(const char* path)
{
    struct stat pathStat;
    if(stat(path, &pathStat) != 0){
        return 0; // Treat errors as not a file
    }
    return S_ISREG(pathStat.st_mode) || S_ISLNK(pathStat.st_mode) || S_ISDIR(pathStat.st_mode);
}

const char* matchOption(const char* arg, const char** options)
{
    const char** opt = options;
    while(*opt){
        if(strncmp(arg, *opt, strlen(*opt)) == 0){
            return *opt;
        }
        opt++;
    }
    return NULL;
}


int extractOptionValue(const char* opt, const char* arg, const char* nextArg, const char** outValue)
{
    // This function expects to be called only if the option matches
    size_t optLen = strlen(opt);
    size_t argLen = strlen(arg);

    if(argLen > optLen){
        // Check if the value is attached with '=' for long options
        // or directly for short options
        if(optLen > 2 && opt[0] == '-' && opt[1] == '-'){
            // Long option with '='
            if(arg[optLen] == '='){
                // '=' found, value is attached
                *outValue = arg + optLen + 1;
                return 0;
            }
            *outValue = NULL;
            return -1;
        }else if(optLen > 1 && opt[0] == '-'){
            // Short option directly attached
            *outValue = arg + optLen;
            return 0;
        }else{
            // Invalid arg
            *outValue = NULL;
            return -2;
        }
    }else if(nextArg){
        // Value is in the next argument
        *outValue = nextArg;
        return 1;
    }

    // No value provided
    *outValue = NULL;
    return -2;
}

int extractFlag(const char* opt, const char* arg, const char* nextArg)
{
    const char* outValue = NULL;
    int skipBy = extractOptionValue(opt, arg, nextArg, &outValue);
    if(skipBy < 0){
        if(skipBy != -1){
            return 0; // No value provided, treat as flag
        }
    }else{
        if(outValue == nextArg){
            return 0; // Value provided, but looks like another option, treat as flag
        }
        skipBy = -5;
    }
    return skipBy;
}

int extractOptionIntValue(const char* opt, const char* arg, const char* nextArg, int* outValue)
{
    char* endPtr = NULL;
    const char* strValue = NULL;
    int skipBy = extractOptionValue(opt, arg, nextArg, &strValue);
    if(skipBy < 0) return skipBy;
    
    if(!strValue || strValue[0] == '\0') return -3;

    errno = 0;
    long val = strtol(strValue, &endPtr, 10);
    if(errno != 0 || endPtr == strValue || *endPtr != '\0' || val < INT_MIN || val > INT_MAX){
        return -4; // Invalid integer
    }

    *outValue = (int)val;
    return skipBy;
}

int parseList(const char* str, char delimiter, int (*callback)(const char* item, size_t itemSize, void*data), void* data)
{
    int rc = 0;
    if(!str || !callback) return -1;

    const char* start = str;
    const char* ptr = str;

    while(*ptr){
        if(*ptr == delimiter){
            size_t itemSize = ptr - start;
            if(itemSize > 0){
                if(0!= (rc = callback(start, itemSize, data))){
                    return rc;
                }
            }
            start = ptr + 1;
            ptr = start;
            continue;
        }
        ptr++;
    }

    // Handle the last item if there's no trailing delimiter
    if(ptr != start){
        size_t itemSize = ptr - start;
        return callback(start, itemSize, data);
    }

    return 0;
}

int add_machine_to_list(const char* item, size_t itemSize, void* _ctx)
{
    int arch = EM_NONE;
    lsdelf_ctx* ctx = NULL;
    if(!_ctx || !item || itemSize == 0) return -1;
    ctx = (lsdelf_ctx*)_ctx;

    arch = elf_strn_parse_machine_name(item, itemSize);
    if(arch == EM_NONE){
        fprintf(stderr, "Unknown architecture: '%.*s'\n", (int)itemSize, item);
        return -1;
    }
    add_int_array_item(&ctx->filter_archs, arch);
    return 0;
}

int add_type_to_list(const char* item, size_t itemSize, void* _ctx)
{
    int type = ET_NONE;
    lsdelf_ctx* ctx = NULL;
    if(!_ctx || !item || itemSize == 0) return -1;
    ctx = (lsdelf_ctx*)_ctx;

    if((strncmp(item, "all", sizeof("all")-1) == 0 && itemSize == sizeof("all")-1)
        || (itemSize == 1 && item[0] == 'a')) {
        // Special case for "all"
        add_int_array_item(&ctx->filter_types, ET_NONE);
        add_int_array_item(&ctx->filter_types, ET_REL);
        add_int_array_item(&ctx->filter_types, ET_EXEC);
        add_int_array_item(&ctx->filter_types, ET_DYN);
        add_int_array_item(&ctx->filter_types, ET_CORE);
        return 0;
    }

    type = elf_strn_parse_type_name(item, itemSize);
    if(type != ET_NONE){
        add_int_array_item(&ctx->filter_types, type);
        return 0;
    }
    for(size_t i = 0; i < itemSize; i++){
        type = ET_NONE;
        type=elf_strn_parse_type_name(&item[i], 1);
        if(type == ET_NONE){
            fprintf(stderr, "Unknown type character: '%c' in '%.*s'\n", item[i], (int)itemSize, item);
            return -1;
        }
        add_int_array_item(&ctx->filter_types, type);
    }
    return 0;
}

int add_path_to_list(const char* item, size_t itemSize, void* _ctx)
{
    lsdelf_ctx* ctx = NULL;
    if(!_ctx || !item || itemSize == 0) return -1;
    ctx = (lsdelf_ctx*)_ctx;

    char* path = (char*)malloc(itemSize + 1);
    if(!path) return -1;
    memcpy(path, item, itemSize);
    path[itemSize] = '\0';

    add_str_array_item_move(&ctx->input_paths, path);

    return 0;
}

int add_ignore_pattern(const char* item, size_t itemSize, void* _ctx)
{
    lsdelf_ctx* ctx = NULL;
    if(!_ctx || !item || itemSize == 0) return -1;
    ctx = (lsdelf_ctx*)_ctx;
    char* pattern = NULL;

    // Trim leading and trailing whitespace
    while(itemSize > 0 && (item[0] == ' ' || item[0] == '\t')){
        item++;
        itemSize--;
    }
    while(itemSize > 0 && (item[itemSize - 1] == ' ' || item[itemSize - 1] == '\t')){
        itemSize--;
    }

    //Check if item is inside quotes and remove them
    if(itemSize > 1 && ((item[0] == '"' && item[itemSize - 1] == '"') || (item[0] == '\'' && item[itemSize - 1] == '\''))){
        item++;
        itemSize -= 2;
    }

    if(itemSize == 0) return 0; // Empty pattern after trimming, ignore

    //Check if is an extension pattern (wildcard starting with '*.')
    if(itemSize > 2 && item[0] == '*' && item[1] == '.'){
        //Check if no other wildcards are present
        int hasOtherWildcards = 0;
        for(size_t i = 2; i < itemSize; i++){
            if(item[i] == '*'){
                hasOtherWildcards = 1;
                break;
            }
        }
        if(!hasOtherWildcards){
            // Add to ignore_extension_patterns without the leading '*'
            pattern = (char*)calloc(1,itemSize); // itemSize - 1 for leading '*' + 1 for null terminator
            if(!pattern) return -1;
            memcpy(pattern, item + 1, itemSize - 1);

            add_str_array_item(&ctx->ignore_extension_patterns, pattern);
            return 0;
        }
    }

    pattern =(char*)malloc(itemSize + 1);
    if(!pattern) return -1;
    memcpy(pattern, item, itemSize);
    pattern[itemSize] = '\0';
    add_str_array_item_move(&ctx->ignore_patterns, pattern);

    return 0;
}

int add_symbol_to_list(const char* item, size_t itemSize, void* _ctx)
{
    lsdelf_ctx* ctx = NULL;
    if(!_ctx || !item || itemSize == 0) return -1;
    ctx = (lsdelf_ctx*)_ctx;

    // Check if symbol type is specified with 'type:symbol'
    const char* colonPos = memchr(item, ':', itemSize);
    const char* symName = item;
    elf_symbol sym = {0};

    if(!colonPos)
    {
        // No type specified, treat as any type
        if(itemSize == 0) return -1;
        sym.type = -1;
        sym.name = (char*)malloc(itemSize + 1);
        if(!sym.name) return -1;
        memcpy(sym.name, item, itemSize);
        sym.name[itemSize] = '\0';
        add_elf_symbol_array_item_move(&ctx->filter_symbols, sym);
        return 0;
    }

    symName = colonPos + 1;

    size_t typeSize = colonPos - item;
    size_t symNameSize = itemSize - typeSize - 1; // -1 for the colon
    if(typeSize == 0 || symNameSize == 0) return -1; // Invalid format

    // Parse symbol type
    if((strncmp(item, "function", sizeof("function")-1) == 0 && typeSize == sizeof("function")-1) ||
        (strncmp(item, "func", sizeof("func")-1) == 0 && typeSize == sizeof("func")-1) ||
        (item[0] == 'f' && typeSize == 1)){
        sym.type = STT_FUNC;
    }else if((strncmp(item, "object", sizeof("object")-1) == 0 && typeSize == sizeof("object")-1) ||
        (strncmp(item, "obj", sizeof("obj")-1) == 0 && typeSize == sizeof("obj")-1) ||
        (item[0] == 'o' && typeSize == 1)){
        sym.type = STT_OBJECT;
    }else if((strncmp(item, "any", sizeof("any")-1) == 0 && typeSize == sizeof("any")-1) ||
        (item[0] == 'a' && typeSize == 1)){
        sym.type = -1; // Special value to indicate any type
    }else{
        fprintf(stderr, "Unknown symbol type: '%.*s' in '%.*s'\n", (int)typeSize, item, (int)itemSize, item);
        return -1;
    }
    sym.name = (char*)malloc(symNameSize + 1);
    if(!sym.name) return -1;
    memcpy(sym.name, symName, symNameSize);
    sym.name[symNameSize] = '\0';
    add_elf_symbol_array_item_move(&ctx->filter_symbols, sym);
    return 0;
}

void printUsage(const char* progName)
{
    fprintf(stderr, "Usage: %s [options] <input paths...>\n", progName);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -l<lib>, --lib  <lib>    Filter by linked library (e.g., -lfoo, -l libfoo, --libfoo, --lib libfoo)\n");
    fprintf(stderr, "  -a, --arch <arch>        Filter by architecture (e.g., x86, x86_64, arm, aarch64, ...)\n");
    fprintf(stderr, "  -t, --type <type>        Filter by type (default exec + shared)\n");
    fprintf(stderr, "                               relocatable, rel, r,\n");
    fprintf(stderr, "                               executable, exec, e,\n");
    fprintf(stderr, "                               dynamic, dyn, d,\n");
    fprintf(stderr, "                               shared, s,\n");
    fprintf(stderr, "                               core, c,\n");
    fprintf(stderr, "                               all, a\n");
    fprintf(stderr, "  -s, --symbol <t:?sym>    Filter by symbol (e.g., -sfoo, -s foo, --symbol=foo, --symbol foo)\n");
    fprintf(stderr, "                           Optionally specify symbol type with 'type:symbol' \n");
    fprintf(stderr, "                           (e.g., --symbol=func:foo --symbol func:foo)\n");
    fprintf(stderr, "                           where type can be one of:\n");
    fprintf(stderr, "                               func, f: function symbol\n");
    fprintf(stderr, "                               object, obj, o: object symbol\n");
    fprintf(stderr, "                               any, a: any symbol type\n");
    fprintf(stderr, "  --strict                 Only match the exact type specified (don't treat ET_EXEC as matching ET_DYN and vice versa)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -T, --test               Run in test mode. Return 0 if all input paths are valid ELF files\n");
    fprintf(stderr, "                           otherwise return the index of the first file provided that is not a valid ELF file\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -R, --recursive          Recursively search directories for ELF files\n");
    fprintf(stderr, "  -d, --depth <n>          Set the recursion depth (default is 1)\n");
    fprintf(stderr, "  -I, --ignore <pattern>   Ignore files matching the pattern\n");
    fprintf(stderr, "                           (one pattern per line, supports wildcards)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -L, --list               Print in list format\n");
    fprintf(stderr, "  -P, --full-path          Print relative path instead of just filename\n");
    fprintf(stderr, "  --real-path              Print real path instead of filename\n");
    fprintf(stderr, "  -F, --pretty             Pretty format (only applies with --list)\n");
    fprintf(stderr, "  --no-color               Disable colorized output\n");
    fprintf(stderr, "  -1                       Print only the filename (no path)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  --show-arch=y|n          Show architecture in output (default: yes)\n");
    fprintf(stderr, "  --show-type=y|n          Show type in output (default: yes)\n");
    fprintf(stderr, "  --show-libs=y|n|m        Show linked libraries in output (default: yes)\n");
    fprintf(stderr, "                           If 'm' is specified, show linked libraries only if they match the filter\n");
    fprintf(stderr, "  --show-symbols=y|n|m     Show symbols in output (default: no)\n");
    fprintf(stderr, "                           If 'm' is specified, show symbols only if they match the filter\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -v, --verbose            Enable verbose output\n");
    fprintf(stderr, "  --config <file>          Use specified config file\n");
    fprintf(stderr, "  --no-config              Don't load configuration from ~/.lselfrc\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  --version                Show version information\n");
    fprintf(stderr, "  -h, --help               Show this help message\n");
}

int parseBoolValue(const char* str, int* outValue)
{
    if(strcmp(str, "1") == 0 || strcasecmp(str, "true") == 0 || strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0 || strcasecmp(str, "y") == 0){
        *outValue = 1;
        return 0;
    }else if(strcmp(str, "0") == 0 || strcasecmp(str, "false") == 0 || strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0 || strcasecmp(str, "n") == 0){
        *outValue = 0;
        return 0;
    }
    return -1; // Invalid boolean value
}

#define DEFAULT_CONFIG_FILE ".lselfrc"
int loadConfig(lsdelf_ctx* ctx, const char* configPath)
{
    int error =0;
    struct stat st = {0};
    if(stat(configPath, &st) != 0){
        error = errno;
        switch(error){
            case ENOENT:
                return error;
            case EACCES:
                fprintf(stderr, "Warning: Unable to read configuration file '%s', check permissions and try again\n", configPath);
                return error;
            default:
                fprintf(stderr, "Warning: Unable to read configuration file '%s', what: %d (%s)\n", configPath, error, strerror(error));
                return error;
        }
    }

    FILE* configFile = fopen(configPath, "r");
    if(!configFile){
        return errno;
    }

    //Read configurations consisting of [property]=[attribute]
    //Accepted configurations:
    //recursive=[0|1|true|false|yes|no|on|off|y|n]
    //depth=[n]; n>=0
    //list=[0|1|true|false|yes|no|on|off|y|n]
    //pretty=[0|1|true|false|yes|no|on|off|y|n]
    //full_path=[0|1|true|false|yes|no|on|off|y|n]
    //colorize=[0|1|true|false|yes|no|on|off|y|n]
    //strict=[0|1|true|false|yes|no|on|off|y|n]
    //oneline=[0|1|true|false|yes|no|on|off|y|n]
    //exclude=[pattern]; supports wildcards, can be specified multiple times or as a comma-separated list

    char* line = NULL;
    int lineNum = 0;
    size_t len = 0;
    ssize_t read;
    while((read = getline(&line, &len, configFile)) != -1){
        lineNum++;
        // Remove trailing newline
        if(read > 0 && line[read - 1] == '\n'){
            line[read - 1] = '\0';
            read--;
        }
        // Skip empty lines
        if(read == 0){
            if(line){
                free(line);
                line = NULL;
                len = 0;
            }
            continue;
        }

        //Skip comments
        if(line[0] == '#'){
            free(line);
            line = NULL;
            len = 0;
            continue;
        }

        char* equalsSign = strchr(line, '=');
        if(!equalsSign){
            fprintf(stderr, "Invalid configuration at line %d '%s' in config file '%s'\n", lineNum, line, configPath);
            free(line);
            fclose(configFile);
            return -1;

            line = NULL;
            len = 0;
            continue;
        }

        *equalsSign = '\0';
        char* property = line;
        char* value = equalsSign + 1;

        #define PARSE_BOOL_OR_WARN(_value, _name, _target) \
            if(parseBoolValue(_value, (_target)) != 0){ \
                fprintf(stderr, "Invalid value at line %d '%s' for '" _name "' in config file '%s'\n", lineNum, _value, configPath); \
                free(line); \
                fclose(configFile); \
                return -1; \
            }

        if(strcmp(property, "recursive") == 0){
            PARSE_BOOL_OR_WARN(value, "recursive", &ctx->recursive);
            if(ctx->recursive){
                ctx->depth = 0; // Unlimited depth when recursive is true
            } else {
                ctx->depth = 1; // Default depth when not recursive
            }
        }else if(strcmp(property, "depth") == 0){
            char* endPtr = NULL;
            long depth = strtol(value, &endPtr, 10);
            if(endPtr == value || *endPtr != '\0' || depth < 0){
                fprintf(stderr, "Invalid value at line %d '%s' for 'depth' in config file '%s'\n", lineNum, value, configPath);
                free(line);
                fclose(configFile);
                return -1;
            }
            ctx->depth = (int)depth;
        }else if(strcmp(property, "list") == 0){
            PARSE_BOOL_OR_WARN(value, "list", &ctx->asList);
        } else if (strcmp(property, "pretty") == 0){
            PARSE_BOOL_OR_WARN(value, "pretty", &ctx->prettyFormat);
        }else if(strcmp(property, "full_path") == 0){
            PARSE_BOOL_OR_WARN(value, "full_path", &ctx->printFullPath);
        }else if(strcmp(property, "real_path") == 0){
            PARSE_BOOL_OR_WARN(value, "real_path", &ctx->printRealPath);
        }else if(strcmp(property, "colorize") == 0){
            PARSE_BOOL_OR_WARN(value, "colorize", &ctx->colorize);
        } else  if(strcmp(property, "strict") == 0){
            PARSE_BOOL_OR_WARN(value, "strict", &ctx->strictType);
        }else if(strcmp(property, "oneline") == 0){
            PARSE_BOOL_OR_WARN(value, "oneline", &ctx->printOnePerLine);
        }else if(strcmp(property, "show_arch") == 0){
            PARSE_BOOL_OR_WARN(value, "show_arch", &ctx->showArch);
        }else if(strcmp(property, "show_type") == 0){
            PARSE_BOOL_OR_WARN(value, "show_type", &ctx->showType);
        }else if(strcmp(property, "show_libs") == 0){
            if(strcmp(value, "m") == 0 || strcmp(value, "match") == 0){
                ctx->showLibs = 2; // Show libs only if they match the filter
            }else{
                PARSE_BOOL_OR_WARN(value, "show_libs", &ctx->showLibs);
            }
        }else if(strcmp(property, "show_symbols") == 0){
            if(strcmp(value, "m") == 0 || strcmp(value, "match") == 0){
                ctx->showSymbols = 2; // Show symbols only if they match the filter
            }else{
                PARSE_BOOL_OR_WARN(value, "show_symbols", &ctx->showSymbols);
            }
        }
        else if(strcmp(property, "exclude") == 0){
            // Support comma-separated list of patterns
            if(0 != parseList(value, ',', add_ignore_pattern, ctx)){
                fprintf(stderr, "Failed to parse 'exclude' patterns at line %d in config file '%s'\n", lineNum, configPath);
                free(line);
                fclose(configFile);
                return -1;
            }
        }else if(strcmp(property, "type") == 0){
            if(0 != parseList(value, ',', add_type_to_list, ctx)){
                fprintf(stderr, "Failed to parse 'type' at line %d in config file '%s'\n", lineNum, configPath);
                free(line);
                fclose(configFile);
                return -1;
            }
        }else if(strcmp(property, "arch") == 0){
            if(0 != parseList(value, ',', add_machine_to_list, ctx)){
                fprintf(stderr, "Failed to parse 'arch' at line %d in config file '%s'\n", lineNum, configPath);
                free(line);
                fclose(configFile);
                return -1;
            }
        }
        else{
            fprintf(stderr, "Unknown configuration property '%s' in config file '%s'\n", property, configPath);
            free(line);
            fclose(configFile);
            return -1;
        }
    }

    if(line) free(line);
    fclose(configFile);
    return 0;
}

int parseArgs(lsdelf_ctx* ctx, int argc, char** argv, int canReloadConfig)
{
    int needsConfigReload = 0;
    const char* newConfigFile=NULL;
    int typeSet = 0;
    int archSet = 0;
    
    #define OPTIONS(...) (const char*[]) { __VA_ARGS__, NULL }

    int i = 1;
    while(i < argc){
        const char* currentArg = argv[i];
        const char* nextArg = (i + 1 < argc) ? argv[i + 1] : NULL;

        const char* matchedOpt = NULL;
        const char* optValue = NULL;
        int skipBy = 0;

        if((matchedOpt = matchOption(currentArg, OPTIONS("-a", "--arch")))){
            if(!archSet){
                release_int_array(&ctx->filter_archs);
                archSet = 1;
            }
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue[0]!='\0'){
                    if(0 != parseList(optValue, ',', add_machine_to_list, ctx)){
                        return -1;
                    }
                }else{
                    skipBy=-3; // Empty value
                }
            }
        }else if((matchedOpt = matchOption(currentArg, OPTIONS("-t", "--type")))){
            if(!typeSet){
                release_int_array(&ctx->filter_types);
                typeSet = 1;
            }
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue[0]!='\0'){
                    if(0 != parseList(optValue, ',', add_type_to_list, ctx)){
                        return -1;
                    }
                }else{
                    skipBy=-3; // Empty value
                }
            }
        }else if((matchedOpt = matchOption(currentArg, OPTIONS("--lib")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue[0]!='\0'){
                    if(strchr(optValue, '.') == NULL){
                        //If library doesn't contain a dot add a wildcard to match any extension (e.g., .so, .dll)
                        size_t len = strlen(optValue);
                        char* libPattern = (char*)malloc(len + 3); // +2 for ".*" and +1 for null terminator
                        if(!libPattern) return -1;
                        snprintf(libPattern, len + 3, "%s.*", optValue);
                        add_str_array_item_move(&ctx->filter_libs, libPattern);                        
                    }else{
                        add_str_array_item(&ctx->filter_libs, optValue);
                    }
                }else{
                    skipBy=-3; // Empty value
                }
            }
        }else if((matchedOpt = matchOption(currentArg, OPTIONS("-l")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue == nextArg && optValue[0] == '-'){
                    // Next argument looks like another option, treat as missing value
                    skipBy = -2;
                }else if(optValue[0]!='\0'){
                    char* libName = NULL;
                    if(optValue == currentArg + 2){ 
                        // libName = optValue - 1;
                        libName = (char*)malloc(strlen(optValue) + 3 + 1); // "lib" + optValue + null terminator
                        if(!libName) return -1;
                        snprintf((char*)libName, strlen(optValue) + 3 + 1, "lib%s", optValue);
                    }else{
                        libName = strdup(optValue);
                    }

                    if(strchr(libName, '.') == NULL){
                        //If library doesn't contain a dot add a wildcard to match any extension (e.g., .so, .dll)
                        size_t len = strlen(libName);
                        char* libPattern = (char*)malloc(len + 3); // +2 for ".*" and +1 for null terminator
                        if(!libPattern) return -1;
                        snprintf(libPattern, len + 3, "%s.*", libName);
                        add_str_array_item_move(&ctx->filter_libs, libPattern);
                        free(libName);
                    }else{
                        add_str_array_item_move(&ctx->filter_libs, libName);
                    }
                }else{
                    skipBy=-3; // Empty value
                }
            }
        } 
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-s", "--symbol")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                if(optValue[0]!='\0'){
                    if(0 != add_symbol_to_list(optValue, strlen(optValue), ctx)){
                        return -1;
                    }
                }
                else{
                    skipBy=-3; // Empty value
                }
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-F", "--pretty")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->prettyFormat = 1;
            }
        }else if((matchedOpt = matchOption(currentArg, OPTIONS("-L", "--list")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->asList = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-R", "--recursive")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->recursive = 1;
                ctx->depth = 0; // Unlimited depth
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-R", "--no-recursive")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->recursive = 0;
                ctx->depth = 1; // Reset to default depth for non-recursive
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-d", "--depth")))){
            skipBy = extractOptionIntValue(matchedOpt, currentArg, nextArg, &ctx->depth);
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--strict")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->strictType = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-I", "--ignore")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue[0]!='\0'){
                    add_ignore_pattern(optValue, strlen(optValue), ctx);
                }else{
                    skipBy=-3; // Empty value
                }
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-P", "--full-path")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->printFullPath = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--real-path")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->printRealPath = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-1")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->printOnePerLine = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--show-arch")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                if(parseBoolValue(optValue, &ctx->showArch) != 0){
                    if(((optValue == nextArg) && (optValue[0] == '-')) || is_path(optValue)){
                        // Next argument looks like another option, treat as missing value
                        skipBy = -2;
                    }else{
                        skipBy = -4; // Invalid value
                    }
                }
            }
            if(skipBy == -2){
                // If no value provided, default to 1 (enabled)
                ctx->showArch = 1;
                skipBy = 0;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--show-type")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                if(parseBoolValue(optValue, &ctx->showType) != 0){
                    if(((optValue == nextArg) && (optValue[0] == '-')) || is_path(optValue)){
                        // Next argument looks like another option, treat as missing value
                        skipBy = -2;
                    }else{
                        skipBy = -4; // Invalid value
                    }
                }
            }
            if(skipBy == -2){
                // If no value provided, default to 1 (enabled)
                ctx->showType = 1;
                skipBy = 0;
            }
        }
         else if((matchedOpt = matchOption(currentArg, OPTIONS("--show-libs")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                if(parseBoolValue(optValue, &ctx->showLibs) != 0){
                    if(strcmp(optValue, "m") == 0){
                        ctx->showLibs = 2;
                    }else{
                        if(((optValue == nextArg) && (optValue[0] == '-')) || is_path(optValue)){
                            // Next argument looks like another option, treat as missing value
                            skipBy = -2;
                        }else{
                            skipBy = -4; // Invalid value
                        }
                    }
                }
            }
            if(skipBy == -2){
                // If no value provided, default to 1 (enabled)
                ctx->showLibs = 1;
                skipBy = 0;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--show-symbols")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                if(parseBoolValue(optValue, &ctx->showSymbols) != 0){
                    if(strcmp(optValue, "m") == 0){
                        ctx->showSymbols = 2;
                    }else{
                        if(((optValue == nextArg) && (optValue[0] == '-')) || is_path(optValue)){
                            // Next argument looks like another option, treat as missing value
                            skipBy = -2;
                        }else{
                            skipBy = -4; // Invalid value
                        }
                    }
                }
            }
            if(skipBy == -2){
                // If no value provided, default to 1 (enabled)
                ctx->showSymbols = 1;
                skipBy = 0;
            }
        } else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-show-arch")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->showArch = 0;
            }
        } else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-show-type")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->showType = 0;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-show-libs")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->showLibs = 0;
            }
        } else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-show-symbols")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->showSymbols = 0;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-T", "--test")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->testMode = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-color")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->colorize = 0;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("-h", "--help")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                return 1;
            }
        }else if((matchedOpt = matchOption(currentArg, OPTIONS("-v", "--verbose")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                ctx->verbose = 1;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--version")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                printf("lself version: %s\n", PROGRAM_VERSION);
                printf("Built on: %s %s\n", __DATE__, __TIME__);
                printf("Written by: Manuel Herrera Juarez\n");
                return 2;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--no-config")))){
            if((skipBy = extractFlag(matchedOpt, currentArg, nextArg)) == 0){
                needsConfigReload = 1;
                newConfigFile = NULL;
            }
        }
        else if((matchedOpt = matchOption(currentArg, OPTIONS("--config")))){
            if((skipBy = extractOptionValue(matchedOpt, currentArg, nextArg, &optValue)) >= 0){
                // Successfully extracted option value
                if(optValue == nextArg && optValue[0] == '-'){
                    // Next argument looks like another option, treat as missing value
                    skipBy = -2;
                }else if(optValue[0]!='\0'){
                    needsConfigReload = 1;
                    newConfigFile = optValue;
                }else{
                    skipBy=-3; // Empty value
                }
            }
        }
        else{
            if(currentArg[0] == '-'){
                // Unknown option
                skipBy = -1;
            }else if(currentArg[0]!='\0'){
                // Positional argument (input file)
                add_path_to_list(currentArg, strlen(currentArg), ctx);
            }
        }

        if(skipBy < 0){
            if(skipBy == -1) {
                fprintf(stderr, "Unknown option '%s'\n", currentArg);
            }else if(skipBy == -2){
                fprintf(stderr, "Expected argument for '%s'\n", matchedOpt);
            }else if(skipBy == -3){
                fprintf(stderr, "Empty argument for '%s'\n", matchedOpt);
            }else if(skipBy == -4){
                fprintf(stderr, "Invalid value for '%s'\n", matchedOpt);
            }else if(skipBy == -5){
                fprintf(stderr, "Flag '%s' does not take a value\n", matchedOpt);
            }
            return -1;
        }

        i+= 1 + skipBy;
    }

    if(needsConfigReload && canReloadConfig){
        //We do this at last to check arguments are valid before reloading config and potentially losing them
        lsdelf_ctx_free(ctx);
        lsdelf_ctx_init(ctx);

        if(newConfigFile){
            if(0 != loadConfig(ctx, newConfigFile)){
                fprintf(stderr, "Error loading configuration from '%s'\n", newConfigFile);
                return -2;
            }
        }
        //Recurse but now with canReloadConfig=0 to avoid infinite recursion
        return parseArgs(ctx, argc, argv, 0);
    }
    
    return 0;
}



int lsdelf_filter_arch(lsdelf_ctx* ctx, elf_ctx* elf)
{
    if(!ctx) return 0;
    if(ctx->filter_archs.count == 0) return 1;
    for(size_t i = 0; i < ctx->filter_archs.count; i++){
        if(elf_ctx_is_machine(elf, ctx->filter_archs.items[i])){
            return 1;
        }
    }
    return 0;
}

int lsdelf_filter_type(lsdelf_ctx* ctx, elf_ctx* elf)
{
    if(!ctx) return 0;
    if(ctx->filter_types.count == 0) return 1;
    for(size_t i = 0; i < ctx->filter_types.count; i++){
        if(elf_ctx_is_type(elf, ctx->filter_types.items[i], ctx->strictType)){
            return 1;
        }
    }
    return 0;
}

int lsdelf_filter_libs(lsdelf_ctx* ctx, elf_ctx* elf)
{
    if(!ctx) return 0;
    if(ctx->filter_libs.count == 0) return 1;

    const Elf64_Dyn* needed = NULL;
    unsigned int offset = 0;
    const char* libName = NULL;
    int foundLib = 0;
    do {
        needed = elf_ctx_get_dynamic_section_entry(elf, DT_NEEDED, offset++);
        if(!needed){
            break;
        }
        libName = elf_ctx_get_dynamic_entry_str(elf, needed);
        if(!libName){
            continue;
        }

        for(size_t i = 0; i < ctx->filter_libs.count; i++){
            if(str_wildcard_match(ctx->filter_libs.items[i], libName)){
                foundLib = 1;
                break;
            }
        }
    }while(needed);
    return foundLib;
}

int lsdelf_filter_symbols(lsdelf_ctx* ctx, elf_ctx* elf)
{
    if(!ctx) return 0;
    if(ctx->filter_symbols.count == 0) return 1;

    for(size_t i=0; i<ctx->filter_symbols.count; i++){
        const char* symPattern = ctx->filter_symbols.items[i].name;
        int symType = ctx->filter_symbols.items[i].type;

        const Elf64_Sym* symbol = NULL;
        for(size_t j=0;; j++){
            symbol = elf_ctx_get_symbol(elf, j);
            if(!symbol){
                break;
            }
            if(symbol->st_name == 0){
                continue; // Skip symbols with no name
            }
            if(symType >= 0 && ELF64_ST_TYPE(symbol->st_info) != symType){
                continue; // Symbol type doesn't match
            }

            const char* currentSymName = elf_ctx_get_symbol_name(elf, symbol);
            if(!currentSymName){
                continue;
            }
            if(str_wildcard_match(symPattern, currentSymName)){
                return 1; // Found a matching symbol
            }
        }
    }    
    return 0;
}

int lsdelf_filter(lsdelf_ctx* ctx, elf_ctx* elf)
{
    if(!ctx || !elf) return 0;
    if(!lsdelf_filter_arch(ctx, elf)) return 0;
    if(!lsdelf_filter_type(ctx, elf)) return 0;
    if(!lsdelf_filter_libs(ctx, elf)) return 0;
    if(!lsdelf_filter_symbols(ctx, elf)) return 0;
    return 1;
}

int lsdelf_filter_path(lsdelf_ctx* ctx, const char* path)
{
    if(!ctx || !path) return 0;
    if(ctx->ignore_patterns.count == 0 && ctx->ignore_extension_patterns.count == 0) return 1;

    const char* filename = get_filename(path);
    if(ctx->ignore_extension_patterns.count > 0){
        const char* ext = strrchr(filename, '.');
        if(ext){
            for(size_t i = 0; i < ctx->ignore_extension_patterns.count; i++){
                if(strcmp(ext, ctx->ignore_extension_patterns.items[i]) == 0){
                    return 0;
                }
            }
        }
    }

    for(size_t i = 0; i < ctx->ignore_patterns.count; i++){
        if(str_wildcard_match(ctx->ignore_patterns.items[i], filename)){
            return 0;
        }
    }
    return 1;
}

elf_ctx lsdelf_process_file(lsdelf_ctx* ctx, const char* filePath)
{
    int err=0;
    elf_ctx elf = {0};
    if(!ctx || !filePath){
        elf.error = EINVAL;
        return elf;
    }

    if(!lsdelf_filter_path(ctx, filePath)){
        elf.error = 0; // Not an error, just filtered out
        return elf;
    }
    elf = elf_ctx_open(filePath);

    if((err=elf_ctx_get_error(&elf)) != 0){
        elf_ctx_close(&elf);
        return elf;
    }

    if(!lsdelf_filter(ctx, &elf)){
        elf_ctx_close(&elf);
        return elf;
    }
    return elf;
}


int fts_comparator(const FTSENT**a, const FTSENT**b)
{
    //Files goes first
    int aIsFile=(a[0]->fts_info == FTS_F);
    int bIsFile=(b[0]->fts_info == FTS_F);

    if(aIsFile && !bIsFile) return -1;
    if(!aIsFile && bIsFile) return 1;
    return strcasecmp(a[0]->fts_name, b[0]->fts_name);
}

// Someday I will refactor this function, it's a mess but it works for now
void print_elf_info(lsdelf_ctx* ctx, elf_ctx* elf, const char* parentDir, int baseNameOnly)
{
    char fullPath[PATH_MAX+1] = {0};
    const char* filePath = elf->filePath;
    char separator = ' ';

    if(ctx->testMode){
        return; // Don't print anything in test mode
    }

    if(ctx->printOnePerLine){
        separator = '\n';
    }

    if(ctx->printRealPath){
        if(realpath(elf->filePath, fullPath)){
            filePath = fullPath;
        }else{
            // If realpath fails, fall back to original path
            filePath = elf->filePath;
        }
    }else if(ctx->printFullPath && parentDir && parentDir[0] != '\0'){
        if(parentDir[strlen(parentDir)-1] == '/'){
            snprintf(fullPath, sizeof(fullPath), "%s%s", parentDir, get_filename(filePath));
        }else{
            snprintf(fullPath, sizeof(fullPath), "%s/%s", parentDir, get_filename(filePath));
        }
        filePath = fullPath;
    }else if(baseNameOnly){
        filePath = get_filename(filePath);
    }
    
    const char* machine = elf_machine_name(elf->ehdr.e_machine);
    const char* type = elf_type_name(elf->ehdr.e_type);
    int isExec = elf_ctx_is_type(elf, ET_EXEC, 1);
    if(!ctx->strictType){
        if(elf->ehdr.e_type == ET_DYN){
            if(elf_ctx_is_type(elf, ET_EXEC, 0)){
                type = elf_type_name(ET_EXEC);
                isExec = 1;
            }
        }
    }

    if(!ctx->asList){
        if(isExec && ctx->colorize){
            printf("\033[32;1m%s\033[0m%c", filePath, separator);
        }else{
            printf("%s%c", filePath, separator);
        }
        return;
    }
    
    if(!ctx->prettyFormat){
        int printedLibs = 0;
        if(ctx->showType == 1){
            printf("%-8s ", type);
        }
        if(ctx->showArch == 1){
            printf("%-8s ", machine);
        }
        if(ctx->showLibs==1){
            const Elf64_Dyn* needed = NULL;
            unsigned int offset = 0;
            int isFirstLib=1;
            do{
                needed = elf_ctx_get_dynamic_section_entry(elf, DT_NEEDED, offset++);
                if(!needed){    
                    break;
                }
                const char* libName = elf_ctx_get_dynamic_entry_str(elf, needed);
                if(!libName){
                    continue;
                }
                if(isFirstLib){
                    if(ctx->showType == 1 || ctx->showArch == 1){
                        printf("  ");
                    }
                    printf("[%s", libName);
                    isFirstLib = 0;
                }else{
                    printf(", %s", libName);
                }
                printedLibs = 1;
            }while(needed);
            if(!isFirstLib){
                printf("]   ");
            }
        }else if(ctx->showLibs==2){
            const char* lastLibName = NULL;
            for(size_t i=0; i<ctx->filter_libs.count; i++){
                const char* libPattern = ctx->filter_libs.items[i];
                const Elf64_Dyn* lib = NULL;
                for(size_t j=0;; j++){
                    lib = elf_ctx_get_dynamic_section_entry(elf, DT_NEEDED, j);
                    if(!lib){
                        break;
                    }
                    const char* libName = elf_ctx_get_dynamic_entry_str(elf, lib);
                    if(!libName){
                        continue;
                    }
                    if(!str_wildcard_match(libPattern, libName)){
                        continue; // Library name doesn't match the pattern
                    }

                    if(!lastLibName){
                        if(ctx->showType == 1 || ctx->showArch == 1){
                            printf("  ");
                        }
                        printf("[");
                    }else{
                        printf("%s, ", lastLibName);
                    }
                    lastLibName = libName;
                }
            }
            if(lastLibName){
                printf("%s]   ", lastLibName);
                printedLibs = 1;
            }
        }
        if(printedLibs || ctx->showType == 1 || ctx->showArch == 1){
            printf(" ");
        }
        if(isExec && ctx->colorize){
            printf("\033[32;1m%s\033[0m\n", filePath);
        }else{
            printf("%s\n", filePath);
        }
    }else{
        int printedSub = 0;
        if(isExec && ctx->colorize){
            printf("── \033[32;1m%s\033[0m", filePath);
        }else{
            printf("── %s", filePath);
        }
        if(ctx->showType == 1){
            printf( " (%s", type);
        }
        if(ctx->showArch == 1){
            if(ctx->showType == 1){
                printf(", %s)\n", machine);
            }else{
                printf(" (%s)\n", machine);
            }
        }else{
            if(ctx->showType == 1){
                printf(")\n");
            }else{
                printf("\n");
            }
        }

        if(ctx->showLibs == 1){
            const char* lastLibName = NULL;
            const Elf64_Dyn* lib = NULL;
            for(size_t j=0;; j++){
                lib = elf_ctx_get_dynamic_section_entry(elf, DT_NEEDED, j);
                if(!lib){
                    break;
                }
                const char* libName = elf_ctx_get_dynamic_entry_str(elf, lib);
                if(!libName){
                    continue;
                }
                if(!lastLibName){
                    // First library, print the header
                    if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                        printf(" ├── Libraries:\n");
                    }else{
                        printf(" └── Libraries:\n");
                    }
                }else{
                    if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                        printf(" │  ├─ %s\n", libName);
                    }else{
                        printf("    ├─ %s\n", libName);
                    }
                }
                lastLibName = libName;
            }
            if(lastLibName){
                if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                    printf(" │  └─ %s\n", lastLibName);
                    printf(" │\n");
                }else{
                    printf("    └─ %s\n", lastLibName);
                    printf("\n");
                }
                printedSub =1;
            }
        } else if(ctx->showLibs == 2){
            const char* lastLibName = NULL;
            for(size_t i=0; i<ctx->filter_libs.count; i++){
                const char* libPattern = ctx->filter_libs.items[i];
                const Elf64_Dyn* lib = NULL;
                for(size_t j=0;; j++){
                    lib = elf_ctx_get_dynamic_section_entry(elf, DT_NEEDED, j);
                    if(!lib){
                        break;
                    }
                    const char* libName = elf_ctx_get_dynamic_entry_str(elf, lib);
                    if(!libName){
                        continue;
                    }
                    if(!str_wildcard_match(libPattern, libName)){
                        continue; // Library name doesn't match the pattern
                    }

                    if(!lastLibName){
                        // First library, print the header
                        if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                            printf(" ├── Matched Libraries:\n");
                        }else{
                            printf(" └── Matched Libraries:\n");
                        }
                    }else{
                        if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                            printf(" │  ├─ %s\n", lastLibName);
                        }else{
                            printf("    ├─ %s\n", lastLibName);
                        }
                    }
                    lastLibName = libName;
                }
            }
            if(lastLibName){
                if(ctx->showSymbols==1 || (ctx->showSymbols==2 && ctx->filter_symbols.count > 0)){
                    printf(" │  └─ %s\n", lastLibName);
                    printf(" │\n");
                }else{
                    printf("    └─ %s\n", lastLibName);
                    printf("\n");
                }
                printedSub =1;
            }
        }
        if(ctx->showSymbols == 1){
            printf(" └── Symbols:\n");
            const char* lastSymName = NULL;

            const Elf64_Sym* symbol = NULL;
            for(size_t j=0;; j++){
                symbol = elf_ctx_get_symbol(elf, j);
                if(!symbol){
                    break;
                }
                if(symbol->st_name == 0){
                    continue; // Skip symbols with no name
                }
                const char* symName = elf_ctx_get_symbol_name(elf, symbol);
                if(!symName){
                    continue;
                }
                if(lastSymName){
                    printf("    ├─ %s\n", lastSymName);
                }
                lastSymName = symName;
            }
            if(lastSymName){
                printf("    └─ %s\n", lastSymName);
                printf("\n");
                printedSub = 1;
            }
        }else if(ctx->showSymbols == 2 && ctx->filter_symbols.count > 0){
            printf(" └── Matched Symbols:\n");
            const char* lastSymName = NULL;

            for(size_t i=0; i<ctx->filter_symbols.count; i++){
                const char* symPattern = ctx->filter_symbols.items[i].name;
                int symType = ctx->filter_symbols.items[i].type;

                const Elf64_Sym* symbol = NULL;
                for(size_t j=0;; j++){
                    symbol = elf_ctx_get_symbol(elf, j);
                    if(!symbol){
                        break;
                    }
                    if(symbol->st_name == 0){
                        continue; // Skip symbols with no name
                    }
                    if(symType >= 0 && ELF64_ST_TYPE(symbol->st_info) != symType){
                        continue; // Symbol type doesn't match
                    }

                    const char* currentSymName = elf_ctx_get_symbol_name(elf, symbol);
                    if(!currentSymName){
                        continue;
                    }
                    if(str_wildcard_match(symPattern, currentSymName)){
                        if(lastSymName){
                            printf("    ├─ %s\n", lastSymName);
                        }
                        lastSymName = currentSymName;
                    }
                }
            }
            if(lastSymName){
                printf("    └─ %s\n", lastSymName);
                printf("\n");
                printedSub =1;
            }
        }
        if(!printedSub){
            printf("\n");
        }
    }    
}

void print_elf_info_list(lsdelf_ctx* ctx, const char* dirName, int depth, elf_ctx_array* elfs)
{
    if(elfs->count == 0) return;
    if(ctx->testMode){
        return; // Don't print anything in test mode
    }
    
    if(depth > 0 || ctx->input_paths.count > 1 || ctx->recursive){
        if(!ctx->printRealPath && (!ctx->printOnePerLine || !ctx->printFullPath)){
            printf("%s:\n", dirName);
        }
    }
    
    for(size_t i = 0; i < elfs->count; i++){
        print_elf_info(ctx, &elfs->items[i], dirName, 1);
    }
    
}

void lsdelf_process_recursive_dir(lsdelf_ctx* ctx, const char* dirPath)
{
    FTS* fts = NULL;
    FTSENT* childrens = NULL;
    FTSENT* node = NULL;
    char* paths[] = { NULL, NULL };
    char realDirPath[PATH_MAX+1] = {0};
    size_t realDirPathLen = 0;

    char* dirPathCopy = NULL;
    int currentDirNodes=0;

    if(!ctx || !dirPath) return;
    paths[0] = (char*)dirPath;

    if(!realpath(dirPath, realDirPath)){
        fprintf(stderr, "Error resolving path '%s': %s\n", dirPath, strerror(errno));
        return;
    }

    realDirPathLen = strnlen(realDirPath, sizeof(realDirPath));
    if(realDirPathLen == 0 || realDirPathLen == sizeof(realDirPath)){
        fprintf(stderr, "Error resolving path '%s': %s\n", dirPath, strerror(errno));
        return;
    }

    fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, fts_comparator);
    if(!fts){
        fprintf(stderr, "Error opening directory '%s': %s\n", dirPath, strerror(errno));
        return;
    }

    childrens = fts_children(fts, 0);
    if(!childrens){
        fprintf(stderr, "Error reading directory '%s': %s\n", dirPath, strerror(errno));
        fts_close(fts);
        return;
    }

    dirPathCopy = strdup(dirPath);
    elf_ctx_array elfsInCurrentDir = {0};
    int lastLevel = 0;

    while((node = fts_read(fts)) != NULL){
        elf_ctx elf = {0};
        if(ctx->depth > 0 && node->fts_level > ctx->depth){
            fts_set(fts, node, FTS_SKIP);
            continue;
        }

        if(node->fts_info != FTS_F){
            if(node->fts_info == FTS_D){
                if(currentDirNodes > 0){
                    if(ctx->processedPathCount > 0 && (!ctx->testMode)){
                        if(!ctx->printRealPath && (!ctx->printOnePerLine || !ctx->printFullPath)){
                            printf("\n");
                            if(!ctx->asList && lastLevel > 0)
                            {
                                printf("\n");
                            }
                        }
                    }
                    print_elf_info_list(ctx, dirPathCopy, lastLevel, &elfsInCurrentDir);
                    ctx->processedPathCount++;
                }
                free(dirPathCopy);
                release_elf_ctx_array(&elfsInCurrentDir);
                dirPathCopy = strdup(node->fts_path);
                elfsInCurrentDir = (elf_ctx_array){0};
                lastLevel = node->fts_level;
                currentDirNodes=0;
            }
            continue;
        }
        elf = lsdelf_process_file(ctx, node->fts_path);
        if(elf_ctx_get_error(&elf) != 0){
            elf_ctx_close(&elf);
            continue;
        }

        if(!elf_ctx_is_open(&elf)){
            elf_ctx_close(&elf);
            continue;
        }

        elf.filePath = strdup(node->fts_path);
        add_elf_ctx_array_item_move_ptr(&elfsInCurrentDir, &elf);
        currentDirNodes++;
    }

    if(currentDirNodes > 0){
        if(ctx->processedPathCount > 0 && (!ctx->testMode)){
            if(!ctx->printRealPath && (!ctx->printOnePerLine || !ctx->printFullPath)){
                printf("\n");
                if(!ctx->asList && lastLevel > 0)
                {
                    printf("\n");
                }
            }

        }
        print_elf_info_list(ctx, dirPathCopy, lastLevel, &elfsInCurrentDir);
        ctx->processedPathCount++;
    }
    if(dirPathCopy){
        free(dirPathCopy);
    }
    release_elf_ctx_array(&elfsInCurrentDir);
    fts_close(fts);
}


int lsdelf_process_path(lsdelf_ctx* ctx, const char* path)
{
    int error  = 0;
    elf_ctx elf = {0};
    if(!ctx) return 1;

    struct stat st = {0};
    if(stat(path, &st) != 0){
        error = errno;
        switch(error){
            case ENOENT:
                fprintf(stderr, "Cannot access '%s': No such file or directory\n", path);
                break;
            case EACCES:
                fprintf(stderr, "Cannot access '%s': Permission denied\n", path);
                break;
            default:
                fprintf(stderr, "Cannot access '%s': Error %d\n", path, errno);
                break;
        }            
        return error;
    }

    if(S_ISDIR(st.st_mode)){
        if(ctx->testMode){
            fprintf(stderr, "Path '%s' is a directory, but test mode is enabled\n", path);
            return ENOTDIR;
        }
        int lastProcessedCount = ctx->processedPathCount;
        if(lastProcessedCount > 0 && ctx->input_paths.count > 1 && !ctx->asList && (!ctx->testMode)){
            if(!ctx->printRealPath && (!ctx->printOnePerLine || !ctx->printFullPath)){
                printf("\n");
            }
        }

        lsdelf_process_recursive_dir(ctx, path);
        if((!ctx->testMode) && lastProcessedCount == ctx->processedPathCount && ctx->input_paths.count > 1){
            // No files were processed, but it was a directory, so we print the directory name with no files
            if(path[strlen(path)-1] != '/'){
                printf("%s/:\n", path);
            }else{
                printf("%s:\n", path);
            }
            ctx->processedPathCount++;
        }
    }else if(S_ISREG(st.st_mode)){
        elf = lsdelf_process_file(ctx, path);
        if(elf_ctx_get_error(&elf) != 0){
            switch(elf.error){
                case 0:
                    // No error, but file was filtered out
                    break;
                case ENOENT:
                    fprintf(stderr, "Cannot access '%s': No such file or directory\n", path);
                    break;
                case EACCES:
                    fprintf(stderr, "Cannot access '%s': Permission denied\n", path);
                    break;
                case EINVAL:
                    if(!ctx->testMode){
                        fprintf(stderr, "File '%s' is not a valid ELF file\n", path);
                    }
                    break;
                default:
                    fprintf(stderr, "Error processing file '%s': Error %d\n", path, elf.error);
                    break;
            }
            elf_ctx_close(&elf);        
            return 1;
        }

        if(!elf_ctx_is_open(&elf)){
            // File was filtered out
            elf_ctx_close(&elf);
            return 1;
        }

        elf.filePath = strdup(path);
        print_elf_info(ctx, &elf, NULL, 0);
        elf_ctx_close(&elf);
        ctx->processedPathCount++;
    }
    return 0;
}

int printConfiguration(lsdelf_ctx* ctx)
{
    if(!ctx) return 0;
    printf("Current Configuration:\n");
    printf("  Recursive: %s\n", ctx->recursive ? "Yes" : "No");
    if(ctx->recursive){
        printf("  Depth: %d\n", ctx->depth == 0 ? -1 : ctx->depth);
    }
    printf("  List Format: %s\n", ctx->asList ? "Yes" : "No");
    printf("  Pretty Format: %s\n", ctx->prettyFormat ? "Yes" : "No");
    printf("  Full Path: %s\n", ctx->printFullPath ? "Yes" : "No");
    printf("  Colorize: %s\n", ctx->colorize ? "Yes" : "No");
    printf("  Strict Type Matching: %s\n", ctx->strictType ? "Yes" : "No");
    printf("  One Per Line: %s\n", ctx->printOnePerLine ? "Yes" : "No");
    printf("  Show Architecture: %s\n", ctx->showArch == 1 ? "Yes" : "No");
    printf("  Show Type: %s\n", ctx->showType == 1 ? "Yes" : "No");
    printf("  Show Libraries: %s\n", ctx->showLibs == 1 ? "Yes" : (ctx->showLibs == 2 ? "Matched Only" : "No"));
    printf("  Show Symbols: %s\n", ctx->showSymbols == 1 ? "Yes" : (ctx->showSymbols == 2 ? "Matched Only" : "No"));

    if(ctx->filter_archs.count > 0){
        printf("  Filter Architectures: ");
        for(size_t i = 0; i < ctx->filter_archs.count; i++){
            printf("%s ", elf_machine_name(ctx->filter_archs.items[i]));
        }
        printf("\n");
    }else{
        printf("  Filter Architectures: None\n");
    }

    if(ctx->filter_types.count > 0){
        printf("  Filter Types: ");
        for(size_t i = 0; i < ctx->filter_types.count; i++){
            printf("%s ", elf_type_name(ctx->filter_types.items[i]));
        }
        printf("\n");
    }else{
        printf("  Filter Types: None\n");
    }

    if(ctx->filter_libs.count > 0){
        printf("  Filter Libraries: ");
        for(size_t i = 0; i < ctx->filter_libs.count; i++){
            printf("%s ", ctx->filter_libs.items[i]);
        }
        printf("\n");
    }else{
        printf("  Filter Libraries: None\n");
    }

    if(ctx->ignore_patterns.count > 0){
        printf("  Ignore Patterns: ");
        for(size_t i = 0; i < ctx->ignore_patterns.count; i++){
            printf("%s ", ctx->ignore_patterns.items[i]);
        }
        printf("\n");
    }else{
        printf("  Ignore Patterns: None\n");
    }

    if(ctx->ignore_extension_patterns.count > 0){
        printf("  Ignore Extension Patterns: ");
        for(size_t i = 0; i < ctx->ignore_extension_patterns.count; i++){
            printf("%s ", ctx->ignore_extension_patterns.items[i]);
        }
        printf("\n");
    }else{
        printf("  Ignore Extension Patterns: None\n");
    }
    printf("\n\n");
    return 0;
}

int main(int argc, char* argv[]) {
    int rc = 0;
    int parseArgsResult = 0;
    lsdelf_ctx ctx = {0};
    lsdelf_ctx_init(&ctx);

    char configPath[PATH_MAX+1] = {0};
    const char* homeDir = getenv("HOME");
    if(homeDir){
        snprintf(configPath, sizeof(configPath), "%s/%s", homeDir, DEFAULT_CONFIG_FILE);
        loadConfig(&ctx, configPath);
    }

    parseArgsResult = parseArgs(&ctx, argc, argv,1);
    if(parseArgsResult != 0){
        lsdelf_ctx_free(&ctx);
        if(parseArgsResult != -2 && parseArgsResult != 2){ // Don't print usage if it's a version request or if the error was related to ignore file parsing
            printUsage(argv[0]);
        }
        return parseArgsResult > 0? 0 : 1;
    }

    if(!isatty(STDOUT_FILENO)){
        ctx.colorize = 0; // Disable color if output is not a terminal
    }

    if(ctx.verbose){
        printConfiguration(&ctx);
    }

    if(ctx.input_paths.count == 0){
        if(ctx.testMode){
            fprintf(stderr, "No input paths provided in test mode\n");
            lsdelf_ctx_free(&ctx);
            return 1;
        }
        add_path_to_list(".", 1, &ctx);
    }

    if(ctx.filter_types.count == 0){
        // Default to executable and shared
        if(ctx.testMode){
            add_int_array_item(&ctx.filter_types, ET_NONE);
            add_int_array_item(&ctx.filter_types, ET_REL);
            add_int_array_item(&ctx.filter_types, ET_CORE);
        }
        add_int_array_item(&ctx.filter_types, ET_EXEC);
        add_int_array_item(&ctx.filter_types, ET_DYN);
    }


    for(size_t i = 0; i < ctx.input_paths.count; i++){
        rc = lsdelf_process_path(&ctx, ctx.input_paths.items[i]);
        if(ctx.testMode && rc != 0){
            // In test mode, if any path fails to process, we return 1
            lsdelf_ctx_free(&ctx);
            return i+1; // Return the index of the first failed path (1-based)
        }
    }

    if(!ctx.testMode &&ctx.processedPathCount > 0 && !ctx.asList && ctx.printOnePerLine != 1){
        printf("\n");
    }
    return 0;
}
