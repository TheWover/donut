

#include "donut.h"

int main(int argc, char *argv[]) {
    
    DONUT_CONFIG c;
    int err;
    
    DonutDelete(NULL);
    
    DonutCreate(NULL);
    err = DonutCreate(&c);
    
    DonutDelete(&c);
    return 0;
}


