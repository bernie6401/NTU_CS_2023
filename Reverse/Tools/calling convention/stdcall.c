#include <stdio.h>


__attribute__((stdcall)) void addIntegers(int a, int b, int c) {
    printf("%d", a+b+c);
}

int main() {
    addIntegers(1, 2, 3);
    return 0;
}
