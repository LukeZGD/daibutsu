#ifndef PLOG_H
#define PLOG_H

#include <stdio.h>
#include <stdbool.h>

# define LOG(x, ...) \
do { \
  printf("[sockport2:log] "x"\n", ##__VA_ARGS__); \
} while(0)

# define LOG_ LOG

# define ERR(x, ...) \
do { \
  printf("[sockport2:error] "x"\n", ##__VA_ARGS__); \
} while(0)

# define FATAL(x, ...) \
do { \
  printf("[sockport2:error] FATAL "x"\n", ##__VA_ARGS__); \
} while(0)

# ifdef DEVBUILD
#  define DEVLOG(x, ...) \
do { \
  printf("[sockport2:debug] "x"\n", ##__VA_ARGS__); \
} while(0)
#  define DEVLOG2(x, ...) \
do { \
  printf("[sockport2:debug2] "x"\n", ##__VA_ARGS__); \
} while(0)
# else
#  define DEVLOG(x, ...)
#  define DEVLOG2(x, ...)
# endif

#endif /* PLOG_H */
