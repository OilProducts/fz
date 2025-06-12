// target1.c – single-call stack smash.
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[8];
    fread(buf, 1, 64, stdin);   // no bounds check
    puts("done");
}
