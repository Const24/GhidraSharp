/* Multi-architecture parity fixture for GhidraSharp.
 *
 * No #includes, so `clang -c -target <triple>` compiles it to a relocatable ELF
 * object for any LLVM backend without a sysroot/libc. Ghidra reads the object,
 * detects the language from the ELF e_machine, and we run the parity harness on
 * it (cs vs pyghidra). Spans a few constructs: calls, a loop, pointer/array
 * indexing, a struct, and a global table.
 */
typedef struct {
    int a;
    short b;
    char c;
} Rec;

int g_table[8] = {1, 2, 3, 4, 5, 6, 7, 8};

int add(int a, int b) {
    return a + b;
}

long sum(const int *p, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) {
        s += p[i];
    }
    return s;
}

int rec_get(const Rec *r) {
    return r->a + (int)r->b + (int)r->c;
}

int main(void) {
    Rec r = {add(2, 3), 7, 9};
    return (int)sum(g_table, 8) + rec_get(&r);
}
