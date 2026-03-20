/*
 * File:    utils.h
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

#ifndef UTILS_H
#define UTILS_H

#define BASE_DYNARR_STRUCT(type) \
    type* items; \
    size_t count; \
    size_t capacity;

#define BASE_DYNARR_RELEASE(type, dtor, dtor_ref) \
    if(!arr) return; \
    if(!arr->items) { \
        arr->count = 0; \
        arr->capacity = 0; \
        return; \
    } \
    for(size_t i = 0; i < arr->count; i++){ \
        dtor(dtor_ref arr->items[i]); \
    } \
    free(arr->items); \
    arr->items = NULL; \
    arr->count = 0; \
    arr->capacity = 0;

#define BASE_DYNARR_ADD(type, dup) \
    if(!arr) return; \
    if(arr->count + 1 > arr->capacity){ \
        size_t newCapacity = arr->capacity == 0? 8 : arr->capacity * 2; \
        type* newItems = realloc(arr->items, sizeof(type) * newCapacity); \
        if(!newItems) { \
            return; \
        } \
        arr->items = newItems; \
        arr->capacity = newCapacity; \
    } \
    arr->items[arr->count] = dup(item); \
    arr->count++;

#define DECLARE_DYNARR(type, name, dtor, dtor_ref, dup) \
    typedef struct{ \
        BASE_DYNARR_STRUCT(type) \
    }name; \
    void release_##name(name* arr){ \
        BASE_DYNARR_RELEASE(type, dtor, dtor_ref) \
    } \
    void add_##name##_item(name* arr, const type item){ \
        BASE_DYNARR_ADD(type, dup) \
    } \
    void add_##name##_item_move(name* arr, type item){ \
        BASE_DYNARR_ADD(type, ) \
    }

#define DECLARE_DYNARR_NOCOPY(type, name, dtor, dtor_ref) \
    typedef struct{ \
        BASE_DYNARR_STRUCT(type) \
    }name; \
    void release_##name(name* arr){ \
        BASE_DYNARR_RELEASE(type, dtor, dtor_ref) \
    } \
    void add_##name##_item_move(name* arr, type item){ \
        BASE_DYNARR_ADD(type, ) \
    } \
    void add_##name##_item_move_ptr(name* arr, type* item){ \
        BASE_DYNARR_ADD(type, *) \
    }

#endif // UTILS_H
