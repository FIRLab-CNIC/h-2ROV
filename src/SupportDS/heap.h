#include <stdio.h>
#include <stdlib.h>

#define MAX_ARRAY_SIZE 30

typedef struct {
    int key;
    int frequency;
} ArrayNode;

typedef struct {
    ArrayNode array[MAX_ARRAY_SIZE];
    int arraySize;
} FrequencyArray;

void initFrequencyArray(FrequencyArray *fa);
int find(FrequencyArray *fa, int key);
void shiftRight(FrequencyArray *fa, int from, int to);
void shiftLeft(FrequencyArray *fa, int from, int to);
void increaseFrequency(FrequencyArray *fa, int key);
void decreaseFrequency(FrequencyArray *fa, int key);