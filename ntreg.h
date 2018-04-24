#pragma once

#ifndef _INCLUDE_NTREG_H
#define _INCLUDE_NTREG_H 1

#include <stdio.h>
#include <stdint.h>

/* Datatypes of the values in the registry */
#ifdef _WIN32
#include <Windows.h>
#else
#define REG_NONE                    0  /* No value type */
#define REG_SZ                      1  /* Unicode nul terminated string */
#define REG_EXPAND_SZ               2  /* Unicode nul terminated string + env */
#define REG_BINARY                  3  /* Free form binary */
#define REG_DWORD                   4  /* 32-bit number */
#define REG_DWORD_BIG_ENDIAN        5  /* 32-bit number */
#define REG_LINK                    6  /* Symbolic Link (unicode) */
#define REG_MULTI_SZ                7  /* Multiple Unicode strings */
#define REG_RESOURCE_LIST           8  /* Resource list in the resource map */
#define REG_FULL_RESOURCE_DESCRIPTOR 9 /* Resource list in the hardware description */
#define REG_RESOURCE_REQUIREMENTS_LIST 10  /* Uh? Rait.. */
#define REG_QWORD                   11 /* Quad word 64 bit, little endian */
#endif

#define REG_MAX 12

typedef struct _hive hive;
struct _hive
{
	char *filename;        /* Hives filename */
	FILE*  filedesc;         /* File descriptor (only valid if state == OPEN) */
	long  size;             /* Hives size (filesise) in bytes */
	long  rootofs;          /* Offset of root-node */
	unsigned char *buffer;          /* Files raw contents */
};

typedef enum  {
	HIVE_NODE_DIRCT		= 0x00000001,
	HIVE_NODE_VALUE		= 0x00000002 
}HIVE_NODE_TYPE;

typedef struct _hive_keynode hive_keynode;
struct _hive_keynode
{
	HIVE_NODE_TYPE flag;  // HIVE_NODE_DIRCT
	hive* parent;
	uint32_t offset; // startoffset of the block
	uint32_t* subkeys;
	uint32_t subkey_count;
	uint32_t* values;
	uint32_t value_count;
	char* name;
};

typedef struct _hive_value hive_value;
struct _hive_value
{
	HIVE_NODE_TYPE flag;  // HIVE_NODE_VALUE
	hive_keynode* parent;
	uint32_t offset; // startoffset of the block
	uint32_t data_type;
	uint32_t data_len;
	uint8_t* data;
	char* name;
};

hive* hive_open(const char* filepath);
void hive_close(hive* h);
hive_keynode* hive_openroot(hive* h);
hive_keynode* hive_openkey(hive* key,long offset);
hive_value* hive_openvalue(hive_keynode* h, long offset);
const char* hive_value_type_string(int type);
void hive_close_value(hive_value* v);
void hive_close_key(hive_keynode* key);
void print_hex(const uint8_t* buffer, uint32_t size, uint32_t colume);
void print_keynode(hive_keynode* key);
#endif