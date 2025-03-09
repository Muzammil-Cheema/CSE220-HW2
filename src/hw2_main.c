#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include "hw2.h"


int main() {
	for (int i = -7; i < 8; i++){
        printf("%d mod 4 == %d\n", i, i%4);
    }
    return 0;
}
