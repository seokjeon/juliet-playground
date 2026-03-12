    memset(data, 'A', 50-1); /* fill with 'A's */
        SNPRINTF(dest, strlen(data), "%s", data);
#define SNPRINTF snprintf
