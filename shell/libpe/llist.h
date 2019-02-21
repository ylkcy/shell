#pragma once

#include <stdint.h>
#include <stdlib.h>

typedef struct _ll_item
{
	void     *data;
	_ll_item *next;
}ll_item_t;

typedef struct
{
	ll_item_t *head;
	ll_item_t *tail;
	uint32_t   elements;
}ll_t;

typedef void (*ll_data_free_t) (void *data);

#define ll_foreach( ll, item ) for( ll_item_t *item = (ll)->head; item != NULL; item = item->next )

#define ll_foreach_data( ll, item, type, name ) \
	type *name = NULL; \
	ll_item_t *item = NULL; \
	for( item = (ll)->head, name = item ? (type *)item->data : NULL; item != NULL && ( name = item ? (type *)item->data : NULL ); item = item->next )

void ll_init( ll_t *ll );
void ll_append( ll_t *ll, void *data );
void ll_destroy( ll_t *ll, ll_data_free_t data_free );