#ifndef _ASUS_NVRAM_H
#define _ASUS_NVRAM_H

extern char *nvram_get(const char *name);
extern char *nvram_safe_get(const char *name);
extern int nvram_get_int(const char *name);
extern int nvram_set_int(const char *key, int value);
extern int nvram_match(const char *name, const char *value);
extern int nvarm_set_cmd(const char *arg);
extern int nvram_set(const char *name, const char *value);
extern int nvram_commit();

#endif
