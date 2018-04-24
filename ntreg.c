#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "ntreg.h"
#include <sys/stat.h>
#include <malloc.h>
#include <string.h>

#define SZ_MAX     4096       /* Max unicode strlen before we truncate */
#define KEY_ROOT   0x2c         /* Type ID of ROOT key node */
#define KEY_NORMAL 0x20       /* Normal nk key */
#define ABSPATHLEN 2048

const char *val_types[REG_MAX + 1] = {
	"REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",       /* 0 - 4 */
	"REG_DWORD_BIG_ENDIAN", "REG_LINK",                                     /* 5 - 6 */
	"REG_MULTI_SZ", "REG_RESOUCE_LIST", "REG_FULL_RES_DESC", "REG_RES_REQ", /* 7 - 10 */
	"REG_QWORD"                                                            /* 11     */
};

/* The first page of the registry file is some kind of header, lot of
* it's contents is unknown, and seems to be mostly NULLs anyway.
* Note also, that this is the only place in the registry I've been
* able to find _any_ kind of checksumming
*/

struct regf_header {

	int32_t id;            /* 0x00000000	D-Word	ID: ASCII-"regf" = 0x66676572 */
	int32_t unknown1;      /* 0x00000004	D-Word	???? */
	int32_t unknown2;      /* 0x00000008	D-Word	???? Always the same value as at 0x00000004  */
	char timestamp[8];  /* 0x0000000C	Q-Word	last modify date in WinNT date-format */
	int32_t unknown3;      /* 0x00000014	D-Word	1 */
	int32_t unknown4;      /* 0x00000018	D-Word	3 - probably version #. 2 in NT3.51 */
	int32_t unknown5;      /* 0x0000001C	D-Word	0 */
	int32_t unknown6;      /* 0x00000020	D-Word	1 */
	int32_t ofs_rootkey;   /* 0x00000024	D-Word	Offset of 1st key record */
	int32_t filesize;      /* 0x00000028	D-Word	Size of the data-blocks (Filesize-4kb) */
	int32_t unknown7;      /* 0x0000002C	D-Word	1 */
	char name[0x1fc - 0x2c];   /* Seems like the hive's name is buried here, max len unknown */
	int32_t checksum;      /* 0x000001FC	D-Word	Sum of all D-Words from 0x00000000 to 0x000001FB */
};

/* Security descriptor. I know how it's linked, but don't know
how the real security data is constructed, it may as well
be like the higher level security structs defined by MS in its
includes & NT docs. Currently, I have no use for it.
Note that keys sharing the exact same security settings will
most likely point to the same security descriptor, thus
saving space and making it fast to make objects inherit settings
(is inheritance supported? they speak of security inheritance as a "new"
feature in the filesystem on NT5, even though I think it was
also supported by the lower levels in the earlier versions)
*/
struct sk_key {
	short id;          /* 0x0000	Word	ID: ASCII-"sk" = 0x6B73        */
	short dummy1;      /* 0x0002	Word	Unused                         */
	int32_t  ofs_prevsk;  /* 0x0004	D-Word	Offset of previous "sk"-Record */
	int32_t  ofs_nextsk;  /* 0x0008	D-Word	Offset of next "sk"-Record     */
	int32_t  no_usage;    /* 0x000C	D-Word	usage-counter                  */
	int32_t  len_sk;      /* 0x0010	D-Word	Size of "sk"-record in bytes   */
	char  data[4];     /* Security data up to len_sk bytes               */
};

/* This is the subkeylist/hash structure. NT4.0+.
* ID + count, then count number of offset/4byte "hash". (not true hash)
* Probably changed from the 3.x version to make it faster to
* traverse the registry if you're looking for a specific name
* (saves lookups in 'nk's that have the first 4 name chars different)
*/

struct lf_key {
	int32_t seglen;
	short id;         /* 0x0000	Word	ID: ASCII-"lf" = 0x666C or "lh" = 0x686c */
	short no_keys;    /* 0x0002	Word	number of keys          */
					  /* 0x0004	????	Hash-Records            */
	union {
		struct lf_hash {
			int32_t ofs_nk;    /* 0x0000	D-Word	Offset of corresponding "nk"-Record  */
			char name[4];   /* 0x0004	D-Word	ASCII: the first 4 characters of the key-name,  */
		} hash[1];
		/* WinXP uses a more real hash instead (base 37 of uppercase name chars)  */
		/* 		padded with 0's. Case sensitiv!                         */
		struct lh_hash {
			int32_t ofs_nk;    /* 0x0000	D-Word	Offset of corresponding "nk"-Record  */
			int32_t hash;      /* 0x0004	D-Word	ASCII: the first 4 characters of the key-name,  */
		} lh_hash[1];
	};
};

/* This is the value descriptor.
* If the sign bit (31st bit) in the length field is set, the value is
* stored inline this struct, and not in a seperate data chunk -
* the data then seems to be in the type field, and maybe also
* in the flag and dummy1 field if -len > 4 bytes
* If the name size == 0, then the struct is probably cut short right
* after the val_type or flag.
* The flag meaning is rather unknown.
*/
struct vk_key {
	int32_t seglen;
	/* Offset	Size	Contents                 */
	short id;         /* 0x0000	Word	ID: ASCII-"vk" = 0x6B76  */
	short len_name;   /* 0x0002	Word	name length              */
	int32_t  len_data;   /* 0x0004	D-Word	length of the data       */
	int32_t  ofs_data;   /* 0x0008	D-Word	Offset of Data           */
	int32_t  val_type;   /* 0x000C	D-Word	Type of value            */
	short flag;       /* 0x0010	Word	Flag                     */
	short dummy1;     /* 0x0012	Word	Unused (data-trash)      */
	char  keyname[1]; /* 0x0014	????	Name                     */

};

/* This is the key node (ie directory) descriptor, can contain subkeys and/or values.
* Note that for values, the count is stored here, but for subkeys
* there's a count both here and in the offset-table (lf or li struct).
* What happens if these mismatch is not known.
* What's the classname thingy? Can't remember seeing that used in
* anything I've looked at.
*/
struct nk_key {
	/* Offset	Size	Contents */
	int32_t  seglen;
	uint16_t id;             /*  0x0000	Word	ID: ASCII-"nk" = 0x6B6E                */
	uint16_t type;           /*  0x0002	Word	for the root-key: 0x2C, otherwise 0x20 */
	uint8_t  timestamp[12];  /*  0x0004	Q-Word	write-date/time in windows nt notation */
	int32_t  ofs_parent;     /*  0x0010	D-Word	Offset of Owner/Parent key             */
	int32_t  no_subkeys;     /*  0x0014	D-Word	number of sub-Keys                     */
	uint8_t  dummy1[4];
	int32_t  ofs_lf;         /*  0x001C	D-Word	Offset of the sub-key lf-Records       */
	uint8_t  dummy2[4];
	int32_t  no_values;      /*  0x0024	D-Word	number of values                       */
	int32_t  ofs_vallist;    /*  0x0028	D-Word	Offset of the Value-List               */
	int32_t  ofs_sk;         /*  0x002C	D-Word	Offset of the sk-Record                */
	int32_t  ofs_classnam;   /*  0x0030	D-Word	Offset of the Class-Name               */
	uint8_t  dummy3[16];
	int32_t  dummy4;         /*  0x0044	D-Word	Unused (data-trash)                    */
	uint16_t len_name;       /*  0x0048	Word	name-length                            */
	uint16_t len_classnam;   /*  0x004A	Word	class-name length                      */
	char  keyname[1];     /*  0x004C	????	key-name                               */
};

void* get_hive_node(hive* h, long offset)
{
	if (h == NULL || h->size < offset + 4)  return NULL;
	int seglen = abs(*((int*)(h->buffer + offset)));
	return (h->size < offset + seglen) ? NULL : (h->buffer + offset);
}

hive * hive_open(const char * filepath)
{
	if (filepath == NULL) return NULL;
	FILE* f = fopen(filepath, "rb");
	if (f != NULL)
	{
		// open hive successfully
		struct regf_header header;
		long read_count = fread(&header, 1, sizeof(struct regf_header), f);
		if (read_count == sizeof(struct regf_header) && header.id == 0x66676572)
		{
			fseek(f, 0, SEEK_END);
			long size = ftell(f);
			fseek(f, 0, SEEK_SET);
			unsigned char* buffer = (unsigned char*)malloc(size);
			if (buffer != NULL &&
				fread(buffer, 1, size, f) == size)
			{
				hive* desc = calloc(1, sizeof(hive));
				desc->filename = _strdup(filepath);
				desc->filedesc = f;
				desc->buffer = buffer;
				desc->size = size;
				struct regf_header* header = (struct regf_header*)desc->buffer;
				desc->rootofs = header->ofs_rootkey + 0x1000;
				return desc;
			}
			free(buffer);
		}
		fclose(f);
	}
	return NULL;
}

void hive_close(hive * h)
{
	if (h)
	{
		free(h->buffer);
		free(h->filename);
		if (h->filedesc)
		{
			fclose(h->filedesc);
		}
	}
}

hive_keynode * hive_openroot(hive * h)
{
	return h != NULL ? hive_openkey(h, h->rootofs) : NULL;
}

hive_keynode * hive_openkey(hive* h, long offset)
{
	// validate arguments
	struct nk_key* keynode = get_hive_node(h, offset);
	if (keynode == NULL || keynode->id!= 0x6B6E) return NULL;

	// now we can process nk_key
	hive_keynode* key = calloc(1, sizeof(hive_keynode));
	key->flag = HIVE_NODE_DIRCT;
	key->parent = h;
	key->offset = offset;
	key->name = _strdup(keynode->keyname);
	struct lf_key* subkeys = NULL;
	if (keynode->no_subkeys > 0 &&
		keynode->ofs_lf > 0 &&
		(subkeys = get_hive_node(h, keynode->ofs_lf + 0x1000)) &&
		(subkeys->id == 0x666C || subkeys->id == 0x686C) &&
		subkeys->no_keys > 0)  // double check the number of subkeys
	{
		// get subkey lists
		key->subkey_count = subkeys->no_keys;
		key->subkeys = (uint32_t*)malloc(sizeof(uint32_t)*key->subkey_count);
		struct lh_hash* lh = &subkeys->lh_hash[0];
		uint32_t *cur = key->subkeys;
		for (uint32_t i = 1; i <= key->subkey_count; ++i, lh++, cur++)
		{
			*cur = lh->ofs_nk + 0x1000;
		}
	}
	uint32_t* lv_key = NULL;
	if (keynode->no_values > 0 &&
		keynode->ofs_vallist > 0 &&
		(lv_key = get_hive_node(h, keynode->ofs_vallist + 0x1000)))
	{
		lv_key++;  // skip seglen part which occupies 4 bytes
		key->value_count = keynode->no_values;
		key->values = (uint32_t*)malloc(sizeof(uint32_t)*key->value_count);
		uint32_t* cur = key->values;
		for (uint32_t i = 1; i < key->value_count; ++i, lv_key++,cur++)
		{
			*cur = *lv_key + 0x1000;
		}
	}
	return key;
}

hive_value * hive_openvalue(hive_keynode* keynode, long offset)
{
	if (keynode == NULL || keynode->parent == NULL) return NULL;
	hive* h = keynode->parent;
	struct vk_key* key = get_hive_node(h, offset);
	if (key!=NULL && key->id == 0x6B76)
	{
		if (key->len_name > 0 || 
			(key->len_data>0&&key->ofs_data>0)) // validate ofs_data here because no data can be fetched if it is zero
		{
			hive_value* value = calloc(1, sizeof(hive_value));
			value->flag = HIVE_NODE_VALUE;
			value->parent = keynode;
			value->offset = offset;
			if (key->len_name > 0)
			{
				// len_name may be zero if no name provided
				value->name = _strdup(key->keyname);
			}
			if (key->len_data > 0 && key->ofs_data > 0)
			{
				char* data = get_hive_node(h, key->ofs_data + 0x1000);
				if (data != NULL)
				{
					value->data_len = key->len_data;
					value->data = malloc(value->data_len);
					memcpy(value->data, data + 4, value->data_len);
				}
			}
			value->data_type = key->val_type;
			return value;
		}
	}
	return NULL;
}

const char * hive_value_type_string(int type)
{
	return type < REG_MAX ? val_types[type] : NULL;
}

void hive_close_value(hive_value * v)
{
	if (v!=NULL)
	{
		free(v->name);
		free(v->data);
		free(v);
	}
}

void hive_close_key(hive_keynode * key)
{
	if (key!=NULL)
	{
		free(key->name);
		free(key->subkeys);
		free(key->values);
		free(key);
	}
}

void print_hex(const uint8_t* buffer, uint32_t size, uint32_t colume)
{
	const uint8_t* cur = buffer;
	const uint8_t* end = buffer + size;
	for (uint32_t i = 1; i <= size; ++i, ++cur)
	{
		printf_s(" 0x%02X ", *cur);
		if (i%colume == 0 && i != 0)
		{
			printf_s("\n");
		}
	}
	printf_s("\n");
}

void print_keynode(hive_keynode* key)
{
	printf("dump key node:%s  at offset %d\n", key->name,key->offset);
	printf("subkey count:%d  value count:%d\n", key->subkey_count, key->value_count);
	if (key->subkey_count != 0 && key->subkeys!=NULL)
	{
		printf("subkey list start:\n");
		const uint32_t* end = key->subkeys + key->subkey_count;
		for (const uint32_t* cur = key->subkeys; cur != end; ++cur)
		{
			hive_keynode* subkey = hive_openkey(key->parent, *cur);
			if (subkey != NULL)
			{
				printf_s("name:%s  ---> offset:%d\n", subkey->name, subkey->offset);
				hive_close_key(subkey);
			}
		}
		printf("subkey list end\n");
	}
	if (key->value_count!=0 && key->values!=NULL)
	{
		printf("value start:\n");
		const uint32_t* end = key->values + key->value_count;
		for (const uint32_t* cur = key->values; cur != end; ++cur)
		{
			hive_value* value = hive_openvalue(key, *cur);
			if (value != NULL)
			{
				printf_s("name:%s  type:%s data len:%d at offset:%d \n", 
										value->name, hive_value_type_string(value->data_type),
										value->data_len,value->offset);
				if (value->data_len > 0)
				{
					print_hex(value->data, value->data_len,16);
				}
				hive_close_value(value);
			}
		}
		printf("value end:\n");
	}
}