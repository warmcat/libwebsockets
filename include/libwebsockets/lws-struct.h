/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

typedef enum {
	LSMT_SIGNED,
	LSMT_UNSIGNED,
	LSMT_BOOLEAN,
	LSMT_STRING_CHAR_ARRAY,
	LSMT_STRING_PTR,
	LSMT_ARRAY,
	LSMT_CHILD_PTR,
	LSMT_SCHEMA,

} lws_struct_map_type_eum;

typedef struct lejp_collation {
	struct lws_dll2 chunks;
	int len;
	char buf[LEJP_STRING_CHUNK + 1];
} lejp_collation_t;

typedef struct lws_struct_map {
	const char *colname;
	const struct lws_struct_map *child_map;
	lejp_callback lejp_cb;
	size_t ofs;			/* child dll2; points to dll2_owner */
	size_t aux;
	size_t ofs_clist;
	size_t child_map_size;
	lws_struct_map_type_eum type;
} lws_struct_map_t;

typedef int (*lws_struct_args_cb)(void *obj, void *cb_arg);

typedef struct lws_struct_args {
	const lws_struct_map_t *map_st[LEJP_MAX_PARSING_STACK_DEPTH];
	lws_struct_args_cb cb;
	struct lwsac *ac;
	void *cb_arg;
	void *dest;

	size_t dest_len;
	size_t map_entries_st[LEJP_MAX_PARSING_STACK_DEPTH];
	size_t ac_block_size;
	int subtype;

	struct lwsac *ac_chunks;
	struct lws_dll2_owner chunks_owner;
	size_t chunks_length;
} lws_struct_args_t;

#define LSM_SIGNED(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_SIGNED \
	}

#define LSM_UNSIGNED(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_UNSIGNED \
	}

#define LSM_BOOLEAN(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_BOOLEAN \
	}

#define LSM_CARRAY(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof (((type *)0)->name), \
	  0, \
	  0, \
	  LSMT_STRING_CHAR_ARRAY \
	}

#define LSM_STRING_PTR(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof (((type *)0)->name), \
	  0, \
	  0, \
	  LSMT_STRING_PTR \
	}

#define LSM_ARRAY(ptype, pname, ctype, cname, lejp_cb, cmap, qname) \
	{ \
	  qname, \
	  cmap, \
	  lejp_cb, \
	  offsetof(ptype, pname), \
	  sizeof (ctype), \
	  offsetof(ctype, cname), \
	  LWS_ARRAY_SIZE(cmap), \
	  LSMT_ARRAY \
	}

#define LSM_CHILD_PTR(ptype, pname, ctype, lejp_cb, cmap, qname) \
	{ \
	  qname, \
	  cmap, \
	  lejp_cb, \
	  offsetof(ptype, pname), \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(cmap), \
	  LSMT_CHILD_PTR \
	}

#define LSM_SCHEMA(ctype, lejp_cb, map, schema_name) \
	{ \
	  schema_name, \
	  map, \
	  lejp_cb, \
	  0, \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(map), \
	  LSMT_SCHEMA \
	}

typedef struct lws_struct_serialize_st {
	const struct lws_dll2 *dllpos;
	const lws_struct_map_t *map;
	const char *obj;
	size_t map_entries;
	size_t map_entry;
	size_t size;
	char subsequent;
	char idt;
} lws_struct_serialize_st_t;

enum {
	LSSERJ_FLAG_PRETTY = 1
};

typedef struct lws_struct_serialize {
	lws_struct_serialize_st_t st[LEJP_MAX_PARSING_STACK_DEPTH];

	size_t offset;
	size_t remaining;

	int sp;
	int flags;
} lws_struct_serialize_t;

typedef enum {
	LSJS_RESULT_CONTINUE,
	LSJS_RESULT_FINISH,
	LSJS_RESULT_ERROR
} lws_struct_json_serialize_result_t;

LWS_VISIBLE LWS_EXTERN int
lws_struct_json_init_parse(struct lejp_ctx *ctx, lejp_callback cb,
			   void *user);

LWS_VISIBLE LWS_EXTERN signed char
lws_struct_schema_only_lejp_cb(struct lejp_ctx *ctx, char reason);

LWS_VISIBLE LWS_EXTERN signed char
lws_struct_default_lejp_cb(struct lejp_ctx *ctx, char reason);

LWS_VISIBLE LWS_EXTERN lws_struct_serialize_t *
lws_struct_json_serialize_create(const lws_struct_map_t *map,
				 size_t map_entries, int flags, void *ptoplevel);

LWS_VISIBLE LWS_EXTERN void
lws_struct_json_serialize_destroy(lws_struct_serialize_t **pjs);

LWS_VISIBLE LWS_EXTERN lws_struct_json_serialize_result_t
lws_struct_json_serialize(lws_struct_serialize_t *js, uint8_t *buf,
			  size_t len, size_t *written);
