/* main_win32.c - Apache executable stub file for Win32
 * This file's purpose in life is to load, and call the
 * "real" main function, apache_main(), located in ApacheCore.dll
 *
 * This was done because having the main() function in a DLL,
 * although Win32 allows it, seemed wrong. Also, MSVC++ won't
 * link an executable without at least one object file. This
 * satistifies that requirement.
 */

__declspec(dllexport) int apache_main(int argc, char *argv[]);

int main(int argc, char *argv[]) 
{
    return apache_main(argc, argv);
}
