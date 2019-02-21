#include "llist.h"

#define LL_ITEM_INIT( ITEM ) \
	(ITEM)->data = \
	(ITEM)->next = NULL

#define LL_ITEM_CREATE( DATA ) \
	ll_item_t *item = (ll_item_t *)calloc( 1, sizeof(ll_item_t) ); \
	item->next = NULL; \
	item->data = DATA

void ll_init( ll_t *ll )
{
	ll->head = NULL;
	ll->tail = NULL;
	ll->elements = 0;
}

void ll_append( ll_t *ll, void *data )
{
	LL_ITEM_CREATE( data );

	if( ll->head == NULL )
	{
		ll->head = item;
	}
	else
	{
		ll->tail->next = item;
	}

	ll->tail = item;
	++ll->elements;
}

void ll_destroy( ll_t *ll, ll_data_free_t data_free )
{
	if( ll->elements )
	{
		for( ll_item_t *entry = ll->head; entry != NULL; )
		{
			ll_item_t *next = entry->next;
		
			if( data_free != NULL && entry->data != NULL )
			{
				data_free( entry->data );
			}

			free( entry );

			entry = next;
		}
	}
}