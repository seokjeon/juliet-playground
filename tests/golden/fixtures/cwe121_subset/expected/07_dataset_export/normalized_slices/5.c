    memset(data, 'A', 100-1); /* fill with 'A's */
        SNPRINTF(dest, strlen(data), "%s", data);
#define SNPRINTF snprintf
