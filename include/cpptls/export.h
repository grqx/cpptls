#ifndef LIBCPPTLS_EXPORT_H
#define LIBCPPTLS_EXPORT_H

#ifdef _WIN32
# ifdef LIBCPPTLS_STATIC
#  define LIBCPPTLS_API
# elif defined(LIBTLS_EXPORTS)
#  define LIBCPPTLS_API __declspec(dllexport)
# else
#  define LIBCPPTLS_API __declspec(dllimport)
# endif
#else  // ifdef _WIN32
# define LIBCPPTLS_API
#endif


#endif
