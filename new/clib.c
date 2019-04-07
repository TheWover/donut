

void* memset(void *b, int c, int len) {
    int           i;
    unsigned char *p = (unsigned char*)b;
    i = 0;
    
    __stosb(p, c, len); // will need to change for ARM
    return b;
}