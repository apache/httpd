/* this file is used by TestLib */
int foo ( const char *c )
{
return 0;
}
int main(void) {
    const char *c = '\0';
    (void)foo(c);
    return 0;
}
