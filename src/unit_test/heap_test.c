#include "../SupportDS/heap.h"

int test() {
    FrequencyArray fa;
    initFrequencyArray(&fa);

    int data[] = {1, 3, 2, 1, 4, 3, 2, 1, 5, 3, 2, 1};
    int dataSize = sizeof(data) / sizeof(data[0]);

    // 初始化频率
    for (int i = 0; i < dataSize; i++) {
        increaseFrequency(&fa, data[i]);
    }

    // 增加和减少频率示例
    increaseFrequency(&fa, 1);
    decreaseFrequency(&fa, 3);
    decreaseFrequency(&fa, 2);
    decreaseFrequency(&fa, 2);
    decreaseFrequency(&fa, 5);

    // 输出数组中的数据
    for (int i = 0; i < fa.arraySize; i++) {
        printf("Data: %d, Frequency: %d\n", fa.array[i].key, fa.array[i].frequency);
    }

    return 0;
}
