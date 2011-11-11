#ifndef ILIAS_ILIAS_NET2_EXPORT_H
#define ILIAS_ILIAS_NET2_EXPORT_H


#if defined(WIN32)
#ifdef ilias_net2_EXPORTS
#define ILIAS_NET2_EXPORT __declspec(dllexport)
#define ILIAS_NET2_LOCAL
#else
#define ILIAS_NET2_EXPORT __declspec(dllimport)
#define ILIAS_NET2_LOCAL
#endif /* ilias_common_EXPORT */
#elif defined(__GNUC__)
#define ILIAS_NET2_EXPORT __attribute__ ((visibility ("default")))
#define ILIAS_NET2_LOCAL  __attribute__ ((visibility ("hidden")))
#else
#define ILIAS_NET2_EXPORT
#define ILIAS_NET2_LOCAL
#endif


#endif /* ILIAS_ILIAS_NET2_EXPORT_H */
