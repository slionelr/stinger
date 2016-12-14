//
// Created by messi on 12/6/16.
//

#ifndef COMMON_LOCK_H
#define COMMON_LOCK_H

#include "types.h"

#include <zconf.h>

typedef struct _LOCK
{
    pthread_mutex_t *handle;
} LOCK, * LPLOCK;

LOCK * lock_create( VOID );
VOID lock_acquire( LOCK * lock );
VOID lock_release( LOCK * lock );
VOID lock_destroy( LOCK * lock );

#endif //COMMON_LOCK_H
