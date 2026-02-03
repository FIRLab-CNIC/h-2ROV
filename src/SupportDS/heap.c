#include"heap.h"

// 初始化FrequencyArray
void initFrequencyArray(FrequencyArray *fa) {
    fa->arraySize = 0;
}

// 查找数据
int find(FrequencyArray *fa, int key) {
    for (int i = 0; i < fa->arraySize; i++) {
        if (fa->array[i].key == key) {
            return i;
        }
    }
    return -1;
}

// 右移操作
void shiftRight(FrequencyArray *fa, int from, int to) {
    for (int i = to; i > from; i--) {
        fa->array[i] = fa->array[i - 1];
    }
}

// 左移操作
void shiftLeft(FrequencyArray *fa, int from, int to) {
    for (int i = from; i < to; i++) {
        fa->array[i] = fa->array[i + 1];
    }
}

// 增加频率
void increaseFrequency(FrequencyArray *fa, int key) {
    int index = find(fa, key);
    if (index != -1) {
        fa->array[index].frequency++;
        // 更新顺序
        while (index > 0 && fa->array[index].frequency > fa->array[index - 1].frequency) {
            ArrayNode temp = fa->array[index];
            fa->array[index] = fa->array[index - 1];
            fa->array[index - 1] = temp;
            index--;
        }
    } else {
        if (fa->arraySize < MAX_ARRAY_SIZE) {
            fa->array[fa->arraySize].key = key;
            fa->array[fa->arraySize].frequency = 1;
            // 插入新元素并更新顺序
            int insertIndex = fa->arraySize;
            while (insertIndex > 0 && fa->array[insertIndex - 1].frequency < fa->array[insertIndex].frequency) {
                ArrayNode temp = fa->array[insertIndex];
                fa->array[insertIndex] = fa->array[insertIndex - 1];
                fa->array[insertIndex - 1] = temp;
                insertIndex--;
            }
            fa->arraySize++;
        } else {
            printf("Array overflow\n");
        }
    }
}

// 减少频率
void decreaseFrequency(FrequencyArray *fa, int key) {
    int index = find(fa, key);
    if (index != -1) {
        fa->array[index].frequency--;
        if (fa->array[index].frequency == 0) {
            // 删除元素并更新顺序
            shiftLeft(fa, index, fa->arraySize - 1);
            fa->arraySize--;
        } else {
            // 更新顺序
            while (index < fa->arraySize - 1 && fa->array[index].frequency < fa->array[index + 1].frequency) {
                ArrayNode temp = fa->array[index];
                fa->array[index] = fa->array[index + 1];
                fa->array[index + 1] = temp;
                index++;
            }
        }
    }
}
