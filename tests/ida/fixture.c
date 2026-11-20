/* Input for the IDA integration checks: a few functions that call each other. */
#include <stdio.h>

__attribute__((noinline)) int leaf_add(int a, int b) { return a + b; }

__attribute__((noinline)) int leaf_mul(int a, int b) { return a * b; }

__attribute__((noinline)) int middle(int a) { return leaf_add(a, 3) + leaf_mul(a, 5) + leaf_add(a, 7); }

__attribute__((noinline)) int outer(int a) { return middle(a) + middle(a + 1) + leaf_mul(a, 2); }

int main(int argc, char **argv) {
    (void)argv;
    printf("%d\n", outer(argc) + middle(argc));
    return 0;
}
