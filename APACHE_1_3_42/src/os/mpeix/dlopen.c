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

/*
 *	dlopen()/dlsym()/dlclose()/dlerror() emulation code for MPE
 *
 *	This is not intended to be a 100% complete implementation.
 */

#include "httpd.h"

typedef struct {
  char  libname[PATH_MAX + 3];
  } t_mpe_dld, *p_mpe_dld;

/*
 *	hpunload() is an undocumented and unsupported function used to unload
 *	NMXL library symbols.  While it isn't listed in the Intrinsics manual
 *	or SYSINTR.PUB.SYS, it performs the same level of parameter checking
 *	that a regular intrinsic does.  The parameter contents are the same
 *	as for HPGETPROCPLABEL(), with the exception of symbolname which can
 *	use the wildcard of " @ " which means unload ALL symbols RIGHT NOW.
 */

extern void hpunload(
	int    parms,		/* option extensible hidden parameter */
	char * symbolname,
	char * libname,
	int  * status,
	int  * symboltype,
	int    casesensitive);
	
#ifdef __GNUC__
extern void HPGETPROCPLABEL(
	int    parms,		/* option extensible hidden parameter */
	char * symbolname,
	void * symboladdr,
	int  * status,
	char * libname,
	int    casesensitive,
	int    symboltype,
	int  * datasize,
	int    position,
	int    searchpath,
	int    binding);

extern void HPERRMSG(
	int     parms,		/* option extensible hidden parameter */
	int     displaycode,
	int     depth,
	short   errorproc,
	int     errornum,
	char  * buffer,
	short * buflength,
	int   * status);
#else
#pragma intrinsic HPERRMSG
#pragma intrinsic HPGETPROCPLABEL
#endif

int mpe_dl_status = 0;
char mpe_dl_errmsg[1024];
char mpe_dl_symname[128];
int  mpe_dl_symtype; /* 0=proc, 1=data, 2=malloc, 3=hpunload */

/*
 *	dlopen()
 */

void *dlopen(const char *libname, int flag) {

t_mpe_dld *handle;
char cwd[PATH_MAX+3];
char library[PATH_MAX+3];
void *symaddr;
int datalen;

/* Save the library name in absolute format for later use */
if (libname[0] != '/') {
	getcwd(cwd, sizeof(cwd));
	ap_snprintf(library, sizeof(library), " %s/%s ", cwd, libname);
} else
	ap_snprintf(library, sizeof(library), " %s ", libname);

#define MPE_WITHOUT_MPELX44
#ifdef MPE_WITHOUT_MPELX44
/*
Unfortunately if we simply tried to load the module structure data item
directly in dlsym(), it would complain about unresolved function pointer 
references.

However, if we first load an actual dummy procedure, we can then subsequently 
load the data item without trouble.  Go figure.

This bug is fixed by patch MPELX44A on MPE/iX 6.0 and patch MPELX44B on
MPE/iX 6.5.
*/

/* Load the dummy procedure mpe_dl_stub */
ap_cpystrn(mpe_dl_symname, " mpe_dl_stub ", sizeof(mpe_dl_symname));
mpe_dl_symtype = 0;

HPGETPROCPLABEL(
#ifdef __GNUC__
	8, 
#endif
	mpe_dl_symname, &symaddr, &mpe_dl_status, library, 1, 
	mpe_dl_symtype, &datalen, 1, 0, 0);

/* We consider it to be a failure if the dummy procedure doesn't exist */
/* if (mpe_dl_status != 0) return NULL; */
/* Or not.  If we failed to load mpe_dl_stub, press on and try to load the
   real data item later in dlsym(). */
#endif /* MPE_WITHOUT_MPELX44 */

mpe_dl_symtype = 2;

/* Allocate a handle */
if ((handle = (t_mpe_dld *)malloc(sizeof(t_mpe_dld))) == NULL) return NULL;

/* Initialize the handle fields */
memset(handle, 0, sizeof(t_mpe_dld));

ap_cpystrn(handle->libname,library,sizeof(handle->libname));

return handle;
}

/*
 *	dlsym()
 */

void *dlsym(void *handle, const char *symbol) {

t_mpe_dld *myhandle = handle;
int       datalen;
void *    symaddr = NULL;

ap_snprintf(mpe_dl_symname, sizeof(mpe_dl_symname), " %s ", symbol);
mpe_dl_symtype = 1;

HPGETPROCPLABEL(
#ifdef __GNUC__
	8, 
#endif
	mpe_dl_symname, &symaddr, &mpe_dl_status, myhandle->libname, 1,
	mpe_dl_symtype, &datalen, 1, 0, 0);

if (mpe_dl_status != 0) {
	return NULL;
} else {
	return symaddr;
}

}

/*
 *	dlclose()
 */

int dlclose(void *handle) {

p_mpe_dld myhandle = handle;

mpe_dl_symtype = 3;

/* unload ALL symbols from the library RIGHT NOW */
hpunload(5, " @ ", myhandle->libname, &mpe_dl_status, NULL, 0);

free(handle);

if (mpe_dl_status == 0)
  return 0;
else
  return -1;

}

/*
 *	dlerror()
 */

const char *dlerror(void) {

char errmsg[1024];
short buflen = sizeof(errmsg)-1;
int status;
char prefix[80];

if (mpe_dl_status == 0) return NULL;

switch (mpe_dl_symtype) {
	case 0:
		ap_snprintf(prefix,sizeof(prefix),
		"HPGETPROCPLABEL() failed on procedure%s",mpe_dl_symname);
		break;
	case 1:
		ap_snprintf(prefix,sizeof(prefix),
		"HPGETPROCPLABEL() failed on data item%s",mpe_dl_symname);
		break;
	case 3:
		ap_cpystrn(prefix,"hpunload() failed",sizeof(prefix));
		break;
	default:
		ap_cpystrn(prefix,"Unknown MPE dynaloader error",sizeof(prefix));
		break;
}

/* Obtain the error message for the most recent mpe_dl_status value */
HPERRMSG(
#ifdef __GNUC__
	7,
#endif
	3, 0, 0, mpe_dl_status, (char *)&errmsg, &buflen, &status);

if (status == 0)
  errmsg[buflen] = '\0';
else
  ap_snprintf(errmsg,sizeof(errmsg),
    "HPERRMSG failed (status=%x); MPE loader status = %x",
    status, mpe_dl_status);

ap_snprintf(mpe_dl_errmsg,sizeof(mpe_dl_errmsg),"%s\n%s",prefix,errmsg);

return (char *)&mpe_dl_errmsg;

}
