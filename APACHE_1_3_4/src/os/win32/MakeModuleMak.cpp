#include <fstream.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void MakeMake(const char *szModule,const char *szSource)
    {
    ifstream ifs("Module.mak.tmpl",ios::nocreate);
    assert(ifs.good());
    
    char buf[1024];
    sprintf(buf,"%s.mak",szModule);
    ofstream ofs(buf,ios::trunc);
    for( ; ; )
	{
	ifs.getline(buf,sizeof buf);
	if(ifs.eof())
	    break;
	for(char *s=buf ; *s ; )
	    {
	    char *p=strchr(s,'%');
	    if(!p)
		{
		ofs << s << '\n';
		break;
		}
	    if(!strncmp(p,"%Module%",8))
		{
		ofs.write(s,p-s);
		ofs << szModule;
		s=p+8;
		}
	    else if(!strncmp(p,"%Source%",8))
		{
		ofs.write(s,p-s);
		ofs << szSource;
		s=p+8;
		}
	    else
		{
		ofs.write(s,p-s+1);
		s=p+1;
		}
	    }
	}
    }

void main(int argc,char **argv)
    {
    if(argc < 2 || (argc%2) != 1)
	{
	cerr << argv[0] << " [<module name> <source file>]+\n";
	exit(1);
	}
    for(int n=1 ; n < argc ; n+=2)
	MakeMake(argv[n],argv[n+1]);
    }

