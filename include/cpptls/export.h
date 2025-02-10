#ifndef LIBCPPTLS_EXPORT_H
#define LIBCPPTLS_EXPORT_H

#ifdef _WIN32
# ifdef LIBTLS_STATIC
#  define TLS_CLIENT_API
# elif defined(LIBTLS_EXPORTS)
#  define TLS_CLIENT_API __declspec(dllexport)
# else
#  define TLS_CLIENT_API __declspec(dllimport)
# endif
#else  // ifdef _WIN32
# define TLS_CLIENT_API
#endif


#endif
