//
// Created by messi on 12/6/16.
//

#include "lock.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#ifdef _THREADS
/*
 * Create a new lock. We choose Mutex's over CriticalSections as their appears to be an issue
 * when using CriticalSections with OpenSSL on some Windows systems. Mutex's are not as optimal
 * as CriticalSections but they appear to resolve the OpenSSL deadlock issue.
 */
LOCK * lock_create( VOID )
{
    LOCK * lock = (LOCK *)malloc( sizeof( LOCK ) );
    if( lock != NULL )
    {
        memset( lock, 0, sizeof( LOCK ) );

        if (pthread_mutex_init(lock->handle, NULL) < 0) {
            printf("[LOCK] mutex_init error\n");
        }
    }
    return lock;
}

/*
 * Acquire a lock and block untill it is acquired.
 */
VOID lock_acquire( LOCK * lock )
{
    if( lock != NULL  ) {
        pthread_mutex_lock(lock->handle);
    }
}

/*
 * Release a lock previously held.
 */
VOID lock_release( LOCK * lock )
{
    if( lock != NULL  ) {
        pthread_mutex_unlock(lock->handle);
    }
}

/*
 * Destroy a lock that is no longer required.
 */
VOID lock_destroy( LOCK * lock )
{
    if( lock != NULL  )
    {
        lock_release( lock );

        pthread_mutex_destroy(lock->handle);

        free( lock );
    }
}

#else

LOCK * lock_create( VOID ) { return NULL; }
VOID lock_acquire( LOCK * lock ) {}
VOID lock_release( LOCK * lock ) {}
VOID lock_destroy( LOCK * lock ) {}
#endif