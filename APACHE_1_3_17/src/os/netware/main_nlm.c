/* main_NLM.c - Apache executable stub file for NetWare
 * This file's purpose in life is to load, and call the
 * "real" main function, apache_main(), located in ApacheC.nlm
 */
int apache_main(int argc, char *argv[]);

int main(int argc, char *argv[]) 
{
    return apache_main(argc, argv);
}
