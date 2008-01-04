/* this file is used by TestLib */
/* the extra decl is to shutup gcc -Wmissing-prototypes */
extern int foo (const char *c);
int foo ( const char *c )
{
return *c;
}
int main(void) {
    const char *c = "";
    (void)foo(c);
    return 0;
}
