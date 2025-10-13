/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if defined(LWS_WITH_STRUCT_SQLITE3)
#include <sqlite3.h>
#endif

/*
 * lws_struct provides apis for these transforms
 *
 *    sqlite3 <-> C struct <-> JSON
 *
 * in a "structured" way.
 */

typedef enum {
	LSMT_SIGNED,
	LSMT_UNSIGNED,
	LSMT_BOOLEAN,
	LSMT_STRING_CHAR_ARRAY,
	LSMT_STRING_PTR,
	LSMT_LIST,
	LSMT_CHILD_PTR,
	LSMT_SCHEMA,
	LSMT_BLOB_PTR,

} lws_struct_map_type_eum;

typedef struct lejp_collation {
	struct lws_dll2			chunks;
	int				len;
	char				buf[LEJP_STRING_CHUNK + 1];
} lejp_collation_t;

typedef struct lws_struct_map {
	const char			*colname;
	const struct lws_struct_map	*child_map;
	lejp_callback			lejp_cb;
	size_t				ofs;	/* child dll2; points to dll2_owner */
	size_t				aux;
	size_t				ofs_clist;
	size_t				child_map_size;
	lws_struct_map_type_eum 	type;
	char				json_only;
} lws_struct_map_t;

typedef int (*lws_struct_args_cb)(void *obj, void *cb_arg);

typedef struct lws_struct_args {
	const lws_struct_map_t		*map_st[LEJP_MAX_PARSING_STACK_DEPTH];
	lws_struct_args_cb		cb;
	struct lwsac			*ac;
	void				*cb_arg;
	void				*dest;

	size_t				dest_len;
	size_t				toplevel_dll2_ofs;
	size_t				map_entries_st[LEJP_MAX_PARSING_STACK_DEPTH];
	size_t				ac_block_size;
	int				subtype;

	int				top_schema_index;

	/*
	 * temp ac used to collate unknown possibly huge strings before final
	 * allocation and copy
	 */
	struct lwsac			*ac_chunks;
	struct lws_dll2_owner		chunks_owner;
	size_t				chunks_length;
} lws_struct_args_t;

/*
 * These types apply to both Sqlite3 and JSON representations
 */

#define LSM_SIGNED(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_SIGNED, \
	  0 \
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
	  LSMT_UNSIGNED, \
	  0, \
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
	  LSMT_BOOLEAN, \
	  0, \
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
	  LSMT_STRING_CHAR_ARRAY, \
	  0, \
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
	  LSMT_STRING_PTR, \
	  0 \
	}

#define LSM_LIST(ptype, pname, ctype, cname, lejp_cb, cmap, qname) \
	{ \
	  qname, \
	  cmap, \
	  lejp_cb, \
	  offsetof(ptype, pname), \
	  sizeof (ctype), \
	  offsetof(ctype, cname), \
	  LWS_ARRAY_SIZE(cmap), \
	  LSMT_LIST, \
	  0, \
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
	  LSMT_CHILD_PTR, \
	  0, \
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
	  LSMT_SCHEMA, \
	  0, \
	}

#define LSM_SCHEMA_DLL2(ctype, cdll2mem, lejp_cb, map, schema_name) \
	{ \
	  schema_name, \
	  map, \
	  lejp_cb, \
	  offsetof(ctype, cdll2mem), \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(map), \
	  LSMT_SCHEMA, \
	  0, \
	}

/*
 * These types are the same as above, but they are JSON-ONLY; they
 * do not apply to sqlite3, do not appear as columns in the table etc.
 * This is useful when these values are dynamically added to the
 * struct before creating the JSON representation and do not directly
 * use information stored in the table associated with the sqlite3
 * representation
 */

#define LSM_JO_SIGNED(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_SIGNED, \
	  1 \
	}

#define LSM_JO_UNSIGNED(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_UNSIGNED, \
	  1, \
	}

#define LSM_JO_BOOLEAN(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof ((type *)0)->name, \
	  0, \
	  0, \
	  LSMT_BOOLEAN, \
	  1, \
	}

#define LSM_JO_CARRAY(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof (((type *)0)->name), \
	  0, \
	  0, \
	  LSMT_STRING_CHAR_ARRAY, \
	  1, \
	}

#define LSM_JO_STRING_PTR(type, name, qname) \
	{ \
	  qname, \
	  NULL, \
	  NULL, \
	  offsetof(type, name), \
	  sizeof (((type *)0)->name), \
	  0, \
	  0, \
	  LSMT_STRING_PTR, \
	  1, \
	}

#define LSM_JO_LIST(ptype, pname, ctype, cname, lejp_cb, cmap, qname) \
	{ \
	  qname, \
	  cmap, \
	  lejp_cb, \
	  offsetof(ptype, pname), \
	  sizeof (ctype), \
	  offsetof(ctype, cname), \
	  LWS_ARRAY_SIZE(cmap), \
	  LSMT_LIST, \
	  1, \
	}

#define LSM_JO_CHILD_PTR(ptype, pname, ctype, lejp_cb, cmap, qname) \
	{ \
	  qname, \
	  cmap, \
	  lejp_cb, \
	  offsetof(ptype, pname), \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(cmap), \
	  LSMT_CHILD_PTR, \
	  1, \
	}

#define LSM_JO_SCHEMA(ctype, lejp_cb, map, schema_name) \
	{ \
	  schema_name, \
	  map, \
	  lejp_cb, \
	  0, \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(map), \
	  LSMT_SCHEMA, \
	  1, \
	}

#define LSM_JO_SCHEMA_DLL2(ctype, cdll2mem, lejp_cb, map, schema_name) \
	{ \
	  schema_name, \
	  map, \
	  lejp_cb, \
	  offsetof(ctype, cdll2mem), \
	  sizeof (ctype), \
	  0, \
	  LWS_ARRAY_SIZE(map), \
	  LSMT_SCHEMA, \
	  1, \
	}


/*
 * This is just used to create the table schema, it is not part of serialization
 * and deserialization.  Blobs should be accessed separately.
 */

#define LSM_BLOB_PTR(type, blobptr_name, qname) \
	{ \
	  qname, /* JSON item, or sqlite3 column name */ \
	  NULL, \
	  NULL, \
	  offsetof(type, blobptr_name),       /* member that points to blob */ \
	  sizeof (((type *)0)->blobptr_name),       /* size of blob pointer */ \
	  0,		 /* member holding blob len */ \
	  0, /* size of blob length member */ \
	  LSMT_BLOB_PTR, \
	  0, \
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
	LSSERJ_FLAG_PRETTY	= (1 << 0),
	LSSERJ_FLAG_OMIT_SCHEMA = (1 << 1)
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

/*
 * JSON -> C struct
 */

/**
 * lws_struct_json_init_parse(): prepare to translate JSON to C struct
 *
 * \p ctx: JSON parse context
 * \p cb: the parsing callback
 * \p user: an opaque user pointer
 *
 * Returns 0 if OK else nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_struct_json_init_parse(struct lejp_ctx *ctx, lejp_callback cb,
			   void *user);

LWS_VISIBLE LWS_EXTERN signed char
lws_struct_schema_only_lejp_cb(struct lejp_ctx *ctx, char reason);

LWS_VISIBLE LWS_EXTERN signed char
lws_struct_default_lejp_cb(struct lejp_ctx *ctx, char reason);

/*
 * C struct -> JSON
 */

/**
 * lws_struct_json_serialize_create(): create a C struct -> JSON renderer
 *
 * \p map: the map of members and types
 * \p map_entries: the count of entries in the map
 * \p flags: JSON parsing options
 * \p ptoplevel: the start of the C struct to render
 *
 * Returns an object that manages the stateful translation of a C struct
 * to a JSON representation.
 *
 * Returns a pointer to the object, or NULL on failure.
 */
LWS_VISIBLE LWS_EXTERN lws_struct_serialize_t *
lws_struct_json_serialize_create(const lws_struct_map_t *map,
				 size_t map_entries, int flags,
				 const void *ptoplevel);

/**
 * lws_struct_json_serialize(): output the next buffer of JSON
 *
 * \p js: the management object
 * \p buf: the output fragment buffer
 * \p len: the max size of \p buf
 * \p written: pointer to a size_t to be set to the valid about in buf on exit
 *
 * This emits the next section of JSON for the object being represented
 * by \p js.  You must refer to the return from the function to understand
 * what is in the buffer on exit, LSJS_RESULT_ERROR indicates the function
 * failed and the buffer is invalid, LSJS_RESULT_CONTINUE indicates the
 * buffer is valid, but is a fragment of the full representation and you
 * should call this function again later to get another fragment, and
 * LSJS_RESULT_FINISH indicates the buffer is valid and is the last part
 * of the representation.
 *
 * After seeing LSJS_RESULT_FINISH or LSJS_RESULT_ERROR you should clean
 * up \js by calling lws_struct_json_serialize_destroy() on it
 */
LWS_VISIBLE LWS_EXTERN lws_struct_json_serialize_result_t
lws_struct_json_serialize(lws_struct_serialize_t *js, uint8_t *buf,
			  size_t len, size_t *written);

/**
 * lws_struct_json_serialize_destroy(): destruct a C struct -> JSON renderer
 *
 * \p pjs: pointer to the object to be destroyed
 *
 * The object to be destroyed should have been returned originally from
 * lws_struct_json_serialize_create()
 */
LWS_VISIBLE LWS_EXTERN void
lws_struct_json_serialize_destroy(lws_struct_serialize_t **pjs);

/*
 * Sqlite3
 */

typedef struct sqlite3 sqlite3;

/**
 * lws_struct_sq3_open(): open an sqlite3 database
 *
 * \p context: the lws_context
 * \p sqlite3_path: the filepath to the database file
 * \p create_if_missing: flag to control if the database is created or not if absent
 * \p pdb: pointer to an sqlite3 * to be set to the database handle if successful
 *
 * Returns 0 for success, *pdb is valid, else nonzero for failure
 */
LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_open(struct lws_context *context, const char *sqlite3_path,
		    char create_if_missing, sqlite3 **pdb);

/*
 * lws_struct_sq3_close(): close db handle
 *
 * \p pdb: pointer to sqlite3 * that will be set to NULL
 *
 * *pdb will be closed and set to NULL.
 */
LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_close(sqlite3 **pdb);

/*
 * lws_struct_sq3_create_table(): ensure table exists with correct schema
 *
 * \p pdb: sqlite3 database handle
 * \p schema: map describing table name and schema details
 */

LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_create_table(sqlite3 *pdb, const lws_struct_map_t *schema);

/*
 * struct -> sqlite3 (list)
 */

/**
 * lws_struct_sq3_serialize(): store objects pointed to by owner in the db
 *
 * \p pdb: the open sqlite3 db
 * \p schema: the schema (and db table) to use
 * \p owner: the list of objects to store to the db table
 * \p manual_idx: the starting index for the objects
 *
 */
LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_serialize(sqlite3 *pdb, const lws_struct_map_t *schema,
			 lws_dll2_owner_t *owner, uint32_t manual_idx);

/*
 * struct -> sqlite3 (single)
 */


LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_update(sqlite3 *pdb, const char *table,
		      const lws_struct_map_t *map, size_t map_entries, const void *data,
		      const char *where_col);

LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_upsert(sqlite3 *pdb, const char *table,
		      const lws_struct_map_t *map, size_t map_entries, const void *data,
		      const char *where_col);

/*
 * sqlite3 -> struct(s) in lwsac
 */

LWS_VISIBLE LWS_EXTERN int
lws_struct_sq3_deserialize(sqlite3 *pdb, const char *filter, const char *order,
			   const lws_struct_map_t *schema, lws_dll2_owner_t *o,
			   struct lwsac **ac, int start, int limit);


