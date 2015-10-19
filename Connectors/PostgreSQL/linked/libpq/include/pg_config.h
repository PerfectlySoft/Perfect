#ifdef __BIG_ENDIAN__
 #error "Dont support ppc architecture"
#else
 #ifdef __LP64__
  #include "pg_config_x86_64.h"
 #else
  #include "pg_config_i386.h"
 #endif
#endif

