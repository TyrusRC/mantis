#include <stdlib.h>
void uaf(void) { char *p = malloc(4); free(p); p[0] = 1; }              // ruleid: native-uaf-free-use
void uaf_struct(struct s *q) { free(q); q->x = 2; }                       // ruleid: native-uaf-free-use
void ok_realloc(void) { char *p = malloc(4); free(p); p = malloc(8); p[0] = 1; } // ok
void toctou(const char *path) { if (access(path, R_OK) == 0) { int fd = open(path, 0); } } // ruleid: native-toctou-access
void ok_open(const char *path) { int fd = open(path, 0); }                // ok
char api_key[] = "abcd1234";                                              // ruleid: native-hardcoded-key
char greeting[] = "hello";                                                // ok
