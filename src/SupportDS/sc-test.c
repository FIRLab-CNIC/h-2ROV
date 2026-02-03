#include"sc-vector.h"

#include <stdio.h>

typedef struct{
    uint32_t pfx;
    int masklen;
    int maxlen;
    uint32_t asn;
}w4;

void example_str(void)
{
    w4 it;
	sc_array_def(w4,w4);
	struct sc_array_w4 arr;

	sc_array_init(&arr);

    w4 a,b,c;
    a.asn=0;
    b.asn=1;
    c.asn=2;
	sc_array_add(&arr, a);
	sc_array_add(&arr, b);
	sc_array_add(&arr, c);

	printf("\nDelete first element \n\n");
	sc_array_del(&arr, 0);

	sc_array_foreach (&arr, it) {
		printf("Elem = %d \n", it.asn);
	}

	sc_array_term(&arr);
}

int main(){
    example_str();
}