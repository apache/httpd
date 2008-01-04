/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

