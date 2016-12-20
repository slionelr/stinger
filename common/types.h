//
// Created by messi on 12/6/16.
//

#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <errno.h>
#include <stddef.h>

typedef	char		BOOL;
typedef	char		BOOLEAN;
typedef	BOOL *		LPBOOL;
typedef	char		CHAR;
typedef	CHAR *		PCHAR;
typedef	void *		LPVOID;
typedef	unsigned char		BYTE;
typedef	BYTE *		LPBYTE;


typedef	uint32_t	ULONG;
typedef	uint32_t *	PULONG;
typedef	const char	CSTR;
typedef	const wchar_t	CWSTR;
typedef	unsigned char	UCHAR;
typedef UCHAR *		PUCHAR;
typedef	CSTR *		LPCSTR;
typedef	CWSTR *		LPCWSTR;
typedef	char *		LPSTR;
//typedef	long		DWORD; //TODO: Size problems between linux and freebsd
typedef	int 		DWORD;
typedef	DWORD *		LPDWORD;
typedef	int32_t		LONG;
typedef	LONG *		LPLONG;
typedef	unsigned int	UINT;
typedef	int		HANDLE;
typedef	int		SOCKET;
typedef	void		VOID;
typedef	VOID *		PVOID;
typedef	void *		HMODULE;
typedef	short		SHORT;
typedef unsigned short  USHORT;
typedef uint64_t	QWORD;

#ifndef TRUE
#define TRUE (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif

#define	_strdup				strdup

#ifdef _BSD
#define	ERROR_INSTALL_USEREXIT	EPROGUNAVAIL
#endif

#define ERROR_NOT_FOUND		ENOENT
#define ERROR_NOT_ENOUGH_MEMORY	ENOMEM
#define ERROR_INVALID_PARAMETER	EINVAL
#define ERROR_INVALID_HANDLE   	EINVAL
#define ERROR_INVALID_DATA     	EINVAL
#define ERROR_INVALID_FUNCTION 	EINVAL
#define ERROR_UNSUPPORTED_COMPRESSION	EINVAL
#define	ERROR_NOT_SUPPORTED	EOPNOTSUPP

#define ERROR_SUCCESS 0

#define INVALID_HANDLE_VALUE    (0)
#define WSAEWOULDBLOCK          EWOULDBLOCK

/* SOCKET */
#define SOCKET_ERROR (-1)
#define INVALID_SOCKET (-1)

extern int local_error;
#define WSAGetLastError()	GetLastError()
#define	GetLastError()		(local_error != -1 ? local_error : errno)
#define	SetLastError(x)		(local_error = (x))

#define	__try
#define	__except(x)	if (0)

#endif //COMMON_TYPES_H
