        memset(data, 'A', 100-1); /* fill with 'A's */
        strncat(dest, data, strlen(data));
