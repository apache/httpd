/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/*
 * mod_auth_msql: authentication
 *
 * Rob McCool & Brian Behlendorf.
 *
 * Adapted to Shambhala by rst.
 *
 * Addapted for use with the mSQL database
 * (see ftp:/ftp.bond.edu.au/pub/Minerva/mSQL)
 *
 * Version 1.0 May 1996 - Blame: Dirk.vanGulik@jrc.it.
 *
 * A (sometimes more up to date) version of the documentation
 * can be found at the http://www.apache.org site or at 
 * http://me-www.jrc.it/~dirkx/mod_auth_msql.html.
 * 
 * Outline:
 *
 * This module allows access control using the public domain
 * mSQL database; a fast but limted SQL engine which can be
 * contacted over an internal unix domain protocol as well as
 * over normal inter-machine tcp/ip socket communication.
 *
 * An example table could be:
 *
 * create table user_records (
 * 	  User_id  char(32) primary key,
 *	  Cpasswd  char(32),
 *	[ Xgroup   char(32) ]
 *	  ) \g
 *
 * The user_id can be as long as desired; however some of the
 * popular web browsers truncate, or stop the user from entering
 * names longer than 32 characters. Furthermore the 'crypt' function
 * on your platform might impose further limits. Also use of
 * the 'require users uid [uid..]' directive in the access.conf file,
 * where the user ids are separated by spaces can possibly prohibit the
 * use of spaces in your user-names. Also, not the MAX_FIELD_LEN define
 * somewhere below.
 *
 * To use the above, the following example could be in your access.conf
 * file. Also there is a more elaborate description afther this example.
 *
 * <directory /web/docs/private>
 *
 *  Auth_MSQLhost localhost
 * or
 *  Auth_MSQLhost datab.machine.your.org
 *
 *  		        If this directive is ommited, or set to
 *			localhost, the machine on which apache
 *			runs is assumed, and the faster /dev/msql
 *			communication channel will be used. Otherwise
 *			it is the machine to contact by tcp/ip.
 *
 * Auth_MSQLdatabase    www
 *
 *                      The name of the database on the above machine,
 *			which contains *both* the tables for group and
 *			for user/passwords. Currently it is not possible
 *			to have these split over two databases. Make
 *			sure that the msql.acl (access control file) of
 *			mSQL does indeed allow the effective uid of the
 *			web server read access to this database. Check the
 *			httpd.conf file for this uid.
 *
 * Auth_MSQLpwd_table   user_records
 *
 *                      Here the table which contain the uid/password combination
 *			is specified.
 *
 * Auth_MSQLuid_field	User_id
 * Auth_MSQLpwd_field   Cpasswd
 *
 *			These two directive specify the field names in the 'user_record'
 *			table. If this module is compiled with the BACKWARD_VITEK
 *			compatibility switch, the defaults 'user' and 'password' are
 *			assumed if you do not specify them. Currently the user_id field
 *			*MUST* be a primary key or one must ensure that each user only
 *			occurs *once* in the table. If a UID occurs twice access is
 *			denied by default.
 *
 * Auth_MSQLgrp_table   user_records
 * Auth_MSQLgrp_field	Xgroup
 *
 *                      Optionaly one can also specify a table which contains the
 *			user/group combinations. This can be the same table which
 *			also contains the username/password combinations. However
 *			if a user belongs to two or more groups, one will have to
 *  		        use a differt table with multiple entries.
 *
 * Auth_MSQL_nopasswd	        off
 * Auth_MSQL_Authorative        on
 * Auth_MSQL_EncryptedPasswords on
 *
 *                      These three optional fields (all set to the sensible defaults,
 *			so you really do not have to enter them) are described in more
 *			detail below. If you choose to set these to any other values than
 *			the above be very sure you understand the security implications and
 *			do verify that apache does what you exect it to do.
 *
 * AuthName 		example mSQL realm
 * AuthType		basic
 *
 *                      Normal apache/ncsa tokens for access control
 *
 * <limit get post head>
 *   order deny,allow
 *   allow from all
 *
 *   require valid-user
 *    	     	       'valid-user'; allow in any user which has a valid uid/passwd
 *    	     	       pair in the above pwd_table.
 * or
 *   require user smith jones
 *   	     	      Limit access to users who have a valid uid/passwd pair in the
 *		      above pwd_table AND whose uid is 'smith' or 'jones'. Do note that
 *		      the uid's are separated by 'spaces' for historic (ncsa) reasons.
 *		      So allowing uids with spaces might cause problems.
 *
 *   require group has_paid
 *   	     	      Optionally also ensure that the uid has the value 'has_paid' in the group
 *		      field in the group table.
 *   </limit>
 * </directory>
 *
 * End of the example
 *
 * - full description of all tokens: -
 *
 * Directives:
 *
 * Auth_MSQLhost   	Hostname of the machine running
 *		   	the mSQL demon. The effective uid
 *		   	of the server should be allowed
 *		   	access. If not given, or if it is
 *		   	the magic name 'localhost', it is
 *		   	passed to the mSQL libary as a null
 *	  	 	pointer. This effectively forces it
 *		   	to use /dev/msql rather than the
 *		   	(slower) socket communication.
 *
 * Auth_MSQLdatabase	Name of the database in which the following
 *			table(s) are contained.
 *
 * Auth_MSQLpwd_table	Contains at least the fields with the
 *			username and the (encrypted) password. Each
 *			uid should only occur once in this table and
 *			for performance reasons should be a primary key.
 *			Normally this table is compulsory, but it is
 *			possible to use a fall-through to other methods
 *			and use the mSQL module for group control only;
 *			see the Authorative directive below.
 *
 * Auth_MSQLgrp_table	Contains at least the fields with the
 *			username and the groupname. A user which
 *			is in multiple groups has therefore
 *			multiple entries; this might be some per-
 *			formance problems associated with this; and one
 *			might consider to have separate tables for each
 *			group (rather than all groups in one table) if
 *			your directory structure allows for it.
 *			One only needs to specify this table when doing
 *			group control.
 *
 * Auth_MSQLuid_field	Name of the field containing the username
 * Auth_MSQLpwd_field   Fieldname for the passwords
 * Auth_MSQLgrp_field	Fieldname for the groupname
 *
 *                      Only the fields used need to be specified. When this
 *			module is compiled with the BACKWARD_VITEK option the
 *			uid and pwd field names default to 'user' and 'password'.
 *
 *
 * Auth_MSQL_nopasswd	<on|off>
 *			skip password comparison if passwd field is
 *			empty; i.e. allow 'any' password. This is off
 *			by default; thus to ensure that an empty field
 *			in the mSQL table does not allow people in by
 *			default with a random password.
 *
 * Auth_MSQL_Authorative <on|off>
 *			default is 'on'. When set on, there is no
 *		     	fall through to other authorization methods. So if a
 *			user is not in the mSQL dbase table (and perhaps
 *		        not in the right group) or has the password wrong, then
 *                      he or she is denied access. When this directive is set to
 *			'off' control is passed on to any other authorization
 *			modules, such as the basic auth module wih the htpasswd
 *			file and or the unix-(g)dbm modules.
 *			The default is 'ON' to avoid nasty 'fall-through' sur-
 *			prizes. Do be sure you know what you decide to switch
 *			it off.
 *
 * Auth_MSQL_EncryptedPasswords <on|off>
 * 			default is on. When set on, the values in the
 *			pwd_field are assumed to be crypted using *your*
 *		        machines 'crypt' function; and the incoming password
 *		        is 'crypt'ed before comparison. When this function is
 *			off, the comparison is done directly with the plaintext
 *			entered password. (Yes; http-basic-auth does send the
 *			password as plaintext over the wire :-( ). The default
 *			is a sensible 'on', and I personally thing that it is
 *			a *very-bad-idea* to change this. However a multi
 *			vendor or international environment (which sometimes
 *			leads to different crypts functions) might force you to.
 *
 * Dirk.vanGulik@jrc.it; http://ewse.ceo.org; http://me-www.jrc.it/~dirkx
 * 23 Nov 1995, 24 Feb 1996, 16 May 1996.
 *
 * Version 0.0  First release
 *         0.1  Update to apache 1.00
 *         0.2  added lines which got missing god knows when
 *              and which did the valid-user authentification
 *              no good at all !
 *	   0.3  Added 'Auth_MSQL_nopasswd' option
 *	   0.4  Cleaned out the error messages mess.
 *	   0.6  Inconsistency with gid/grp in comment/token/source
 *  	 	Make sure you really use 'Auth_MSQLgrp_field' as
 *		indicated above.
 *	   0.7  *host to host fixed. Credits go to Rob Stout,
 * 	 	<stout@lava.et.tudelft.nl> for spotting this one.
 *	   0.8  Authorative directive added. See above.
 *	   0.9  palloc return code check(s), should be backward compatible with
 *	   	1.11 version of Vivek Khera <khera@kciLink.com> msql module,
 *		fixed broken err msg in group control, changed command table
 *		messages to make more sense when displayed in that new module
 *		management tool. Added EncryptedPassword on/off functionality.
 *		msqlClose() statements added upon error. Support for persistent
 *		connections with the mSQL database (riscy). Escaping of ' and \.
 *		Replaced some MAX_STRING_LENGTH claims. 
 *	   1.0  removed some error check as they where already done elsehwere
 *	        NumFields -> NumRows (Thanks Vitek). More stack memory.
 *	   1.1	no logging of empty password strings.
 * 	   1.2  Problem with the Backward vitek which cause it to check
 *		even if msql_auth was not configured; Also more carefull
 *		with the authorative stuff; caught by thomas@marvin.calvacom.fr.
 *	   1.3  Even more changes to get it right; that BACKWARD thing was a bad
 *		idea. 
 */


#define ONLY_ONCE 1
/*
 * If the mSQL table containing the uid/passwd combination does
 * not have the uid field as a primary key, it is possible for the
 * uid to occur more than once in the table with possibly different
 * passwords. When this module is compiled with the ONLY_ONCE directive
 * set, access is denied if the uid occures more than once in the
 * uid/passwd table. If you choose not to set it, the software takes
 * the first pair returned and ignores any further pairs. The SQL
 * statement used for this is
 *
 *       "select password form pwd_table where user='uid'"
 *
 * this might lead to unpredictable results. For this reason as well
 * as for performance reasons you are strongly adviced to make the
 * uid field a primary key. Use at your own peril :-)
 */

#undef KEEP_MSQL_CONNECTION_OPEN
/*
 * Normally the (tcp/ip) connection with the database is opened and
 * closed for each SQL query. When the httpd-server and the database
 * are on the same machine, and /dev/msql is used this does not
 * cause a serious overhead. However when your platform does not
 * support this (see the mSQL documentation) or when the web server
 * and the database are on different machines the overhead can be
 * considerable. When the above is set defined the server leaves the
 * connection open; i.e. no call to msqlClose(). If an error occures
 * an attempt is made to re-open the connection for the next http-rq.
 *
 * This has a number of very serious drawbacks
 *  - It costs 2 already rare filedescriptors for each child.
 *  - It costs msql-connections, typically one per child. The (compiled in)
 *    number of connections mSQL can handle is low, typically 6 or 12.
 *    which might prohibit access to the mSQL database for later
 *    processes.
 *  - when a child dies, it might not free that connection properly
 *    or quick enough.
 *  - When errors start to occur, connection/file-descr resources might
 *    become exausted very quickly.
 *
 * In short; use this at your own peril and only in a highly controled and
 * monitored environment
 */

#define BACKWARD_VITEK
#define VITEX_uid_name "user"
#define VITEX_gid_name "passwd"
/* A second mSQL auth module for apache has also been developed by
 * Vivek Khera <khera@kciLink.com> and was subsequently distributed
 * with some early versions of Apache. It can be optained from
 * ftp://ftp.kcilink.com/pub/mod_auth_msql.c*. Older 'vitek' versions had
 * the field/table names compiled in; newer versions, v.1.11 have
 * more access.conf configuration options; however these where
 * choosen not to be in line the 'ewse' version of this module. Also,
 * the 'vitek' module does not give group control or 'empty' password
 * control.
 *
 * To get things slightly more in line this version (0.9) should
 * be backward compatible with the vitek module by:
 *
 *   - adding support for the EncryptedPassword on/off functionality
 *
 *   - adding support for the different spelling fo the 4 configuration
 *     tokens for user-table-name, user/password-field-name and dbase-name.
 *
 *   - setting some field names to a default which used to be hard
 *     coded in in older vitek modules.
 *
 * If this troubles you; remove the 'BACKWARD_VITEX' define.
 */

/* get some sensible values; rather than that big MAX_STRING_LEN,
 */

/* Max field value length limit; well above the limit of some browsers :-)
 */
#define MAX_FIELD_LEN (64)
/* the next two values can be pulled from msql_priv.c, which is *NOT* copied to your
 * /usr/local/include as part of the normal install procedure which comes with
 * mSQL.
 */
#define MSQL_FIELD_NAME_LEN (19)
#define MSQL_TABLE_NAME_LEN (19)
/* We only do the following two queries:
 *
 * - for the user/passwd combination
 *      select PWDFIELD from PWDTABEL where USERFIELD='UID'
 *
 * - optionally for the user/group combination:
 *   	select GROUPFIELD from GROUPTABLE where USERFIELD='UID' and GROUPFIELD='GID'
 *
 * This leads to the following limits: (we are ignoring escaping a wee bit bit here
 * assuming not more than 24 escapes.)
 */

#define MAX_QUERY_LEN (32+24+MAX_FIELD_LEN*2+3*MSQL_FIELD_NAME_LEN+1*MSQL_TABLE_NAME_LEN)


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include <msql.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

typedef struct  {

    char *auth_msql_host;
    char *auth_msql_database;

    char *auth_msql_pwd_table;
    char *auth_msql_grp_table;

    char *auth_msql_pwd_field;
    char *auth_msql_uname_field;
    char *auth_msql_grp_field;

    int auth_msql_nopasswd;
    int auth_msql_authorative;
    int auth_msql_encrypted;

} msql_auth_config_rec;

void *create_msql_auth_dir_config (pool *p, char *d)
{
    msql_auth_config_rec * sec= (msql_auth_config_rec *) pcalloc (p, sizeof(msql_auth_config_rec));

    sec->auth_msql_host        = NULL; /* just to enforce the default 'localhost' behaviour */

    /* just in case, to be nice... */
    sec->auth_msql_database    = NULL;
    sec->auth_msql_pwd_table   = NULL;
    sec->auth_msql_grp_table   = NULL;
    sec->auth_msql_pwd_field   = NULL;
    sec->auth_msql_uname_field = NULL;
    sec->auth_msql_grp_field   = NULL;


    sec->auth_msql_authorative = 1; /* set some defaults, just in case... */
    sec->auth_msql_encrypted   = 1;
    sec->auth_msql_nopasswd    = 0;

#ifdef BACKWARD_VITEK
    /* these are for backward compatibility with the Vivek
     * msql module, as it used to have compile-time defaults.
     */
    sec->auth_msql_uname_field = VITEX_uid_name;
    sec->auth_msql_pwd_field   = VITEX_gid_name;
#endif

    return sec;
}

char *set_passwd_flag (cmd_parms *cmd, msql_auth_config_rec *sec, int arg) {
    sec->auth_msql_nopasswd=arg;
    return NULL;
}

char *set_authorative_flag (cmd_parms *cmd, msql_auth_config_rec *sec, int arg) {
    sec->auth_msql_authorative=arg;
    return NULL;
}

char *set_crypted_password_flag (cmd_parms *cmd, msql_auth_config_rec *sec , int arg) {
    sec->auth_msql_encrypted = arg;
    return NULL;
}

char *msql_set_string_slot (cmd_parms *cmd, char *struct_ptr, char *arg) {
    int offset = (int)cmd->info;
    *(char **)(struct_ptr + offset) = pstrdup (cmd->pool, arg);
    return NULL;
}


command_rec msql_auth_cmds[] = {
{ "Auth_MSQLhost", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_host),
    OR_AUTHCFG, TAKE1, "Host on which the mSQL database engine resides (defaults to localhost)" },

{ "Auth_MSQLdatabase", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_database),
    OR_AUTHCFG, TAKE1, "Name of the mSQL database which contains the password (and possibly the group) tables. " },

{ "Auth_MSQLpwd_table", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_table),
    OR_AUTHCFG, TAKE1, "Name of the mSQL table containing the password/user-name combination" },

{ "Auth_MSQLgrp_table", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_table),
    OR_AUTHCFG, TAKE1, "Name of the mSQL table containing the group-name/user-name combination; can be the same as the password-table." },

{ "Auth_MSQLpwd_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_field),
    OR_AUTHCFG, TAKE1, "The name of the field in the mSQL password table" },

{ "Auth_MSQLuid_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_uname_field),
    OR_AUTHCFG, TAKE1, "The name of the user-name field in the mSQL password (and possibly group) table(s)." },

{ "Auth_MSQLgrp_field", msql_set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_field),
    OR_AUTHCFG, TAKE1,
	"The name of the group field in the mSQL group table; must be set if you want to use groups." },

{ "Auth_MSQL_nopasswd", set_passwd_flag, NULL, OR_AUTHCFG, FLAG,
	"Enable (on) or disable (off) empty password strings; in which case any user password is accepted." },

{ "Auth_MSQL_Authorative", set_authorative_flag, NULL, OR_AUTHCFG, FLAG,
	"When 'on' the mSQL database is taken to be authorative and access control is not passed along to other db or access modules." },

{ "Auth_MSQL_EncryptedPasswords", set_crypted_password_flag, NULL, OR_AUTHCFG, FLAG,
	"When 'on' the password in the password table are taken to be crypt()ed using your machines crypt() function." },

#ifdef BACKWARD_VITEK
/* These 'altenative' tokens should ensure backward compatibility
 * with viteks mSQL module. The only difference is the spelling.
 * Note that these tokens do not allow group configuration.
 */
{ "AuthMSQLHost", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_host),
    OR_AUTHCFG, TAKE1, "mSQL server hostname" },
{ "AuthMSQLDB", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_database),
    OR_AUTHCFG, TAKE1, "mSQL database name" },
{ "AuthMSQLUserTable", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_table),
    OR_AUTHCFG, TAKE1, "mSQL user table name" },
{ "AuthMSQLGroupTable", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_table),
    OR_AUTHCFG, TAKE1, "mSQL group table name" },
{ "AuthMSQLNameField", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_uname_field),
    OR_AUTHCFG, TAKE1, "mSQL User ID field name within table" },
{ "AuthMSQLGroupField", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_grp_field),
    OR_AUTHCFG, TAKE1, "mSQL Group field name within table" },
{ "AuthMSQLPasswordField", set_string_slot,
    (void*)XtOffsetOf(msql_auth_config_rec, auth_msql_pwd_field),
    OR_AUTHCFG, TAKE1, "mSQL Password field name within table" },
{ "AuthMSQLCryptedPasswords", set_crypted_password_flag, NULL,
    OR_AUTHCFG, FLAG, "mSQL passwords are stored encrypted if On" },

#endif

{ NULL }
};

module msql_auth_module;

/* boring little routine which escapes the ' and \ in the
 * SQL query. See the mSQL FAQ for more information :-) on
 * this very popular subject in the msql-mailing list.
 */
char *msql_escape(char *out, char *in, char *msql_errstr) {

  register int i=0,j=0;

  do {
    /* do we need to escape */
    if ( (in[i] == '\'') || (in[i] == '\\')) {

      /* does this fit ? */
      if (j >= (MAX_FIELD_LEN-1)) {
	sprintf(msql_errstr,"Could not escape '%s', longer than %d",in,MAX_FIELD_LEN);
	return NULL;
	};

      out[j++] = '\\'; /* insert that escaping slash for good measure */
    };

    /* Do things still fit ? */
    if (j >= MAX_FIELD_LEN) return NULL;

  } while ( ( out[j++] = in[i++]) != '\0' );

  return out;
}

/* get the password for uname=user, and copy it
 * into r. Assume that user is a string and stored
 * as such in the mSQL database
 */
char *do_msql_query(request_rec *r, char *query, msql_auth_config_rec *sec, int once , char *msql_errstr) {

    	static int 	sock=-1;
    	int		hit;
    	m_result 	*results;
    	m_row 		currow;

 	char 		*result=NULL;
	char		*host=sec->auth_msql_host;

#ifndef KEEP_MSQL_CONNECTION_OPEN
        sock=-1;
#endif

	/* force fast access over /dev/msql */

	if ((host) && (!(strcasecmp(host,"localhost"))))
		host=NULL;

	/* (re) open if nessecary
	 */
    	if (sock==-1) if ((sock=msqlConnect(host)) == -1) {
		sprintf (msql_errstr,
			"mSQL: Could not connect to Msql DB %s (%s)",
			(sec->auth_msql_host ? sec->auth_msql_host : "\'unset, assuming localhost!\'"),
			msqlErrMsg);
		return NULL;
    		}

	/* we always do this, as it avoids book-keeping
	 * and is quite cheap anyway
	 */
    	if (msqlSelectDB(sock,sec->auth_msql_database) == -1 ) {
		sprintf (msql_errstr,"mSQL: Could not select Msql Table \'%s\' on host \'%s\'(%s)",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
		        (sec->auth_msql_host ? sec->auth_msql_host : "\'unset, assuming localhost!\'"),
			msqlErrMsg);
		msqlClose(sock);
		sock=-1;
		return NULL;
		}

    	if (msqlQuery(sock,query) == -1 ) {
		sprintf (msql_errstr,"mSQL: Could not Query database '%s' on host '%s' (%s) with query [%s]",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
		        (sec->auth_msql_host ? sec->auth_msql_host : "\'unset, assuming localhost!\'"),
		        msqlErrMsg,
			( query ? query : "\'unset!\'") );
		msqlClose(sock);
		sock=-1;
		return NULL;
		}

	if (!(results=msqlStoreResult())) {
		sprintf (msql_errstr,"mSQL: Could not get the results from mSQL database \'%s\' on \'%s\' (%s) with query [%s]",
			(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
		        (sec->auth_msql_host ? sec->auth_msql_host : "\'unset, assuming localhost!\'"),
			msqlErrMsg,
			( query ? query : "\'unset!\'") );
		msqlClose(sock);
		sock=-1;
		return NULL;
		};

	hit=msqlNumRows(results);

	if (( once ) && ( hit >1 )) {
          /* complain if there are to many
           * matches.
           */
          sprintf (msql_errstr,"mSQL: More than %d matches (%d) whith query [%s]",
          	   once,hit,( query ? query : "\'unset!\'") );
	} else
	/* if we have a it, try to get it
	*/
        if ( hit )  {
		if ( (currow=msqlFetchRow(results)) != NULL) {
			/* copy the first matching field value */
			if (!(result=palloc(r->pool,strlen(currow[0])+1))) {
				sprintf (msql_errstr,"mSQL: Could not get memory for mSQL %s (%s) with [%s]",
					(sec->auth_msql_database ? sec->auth_msql_database : "\'unset!\'"),
					msqlErrMsg,
					( query ? query : "\'unset!\'") );
				/* do not return right away, to ensure Free/Close.
				 */
				} else {
			        strcpy(result,currow[0]);
			        };
		}
	};

	/* ignore errors, functions are voids anyway. */
	msqlFreeResult(results);

#ifndef KEEP_MSQL_CONNECTION_OPEN
	/* close the connection, unless explicitly told not to. Do note that
	 * we do not have a decent closing option of child termination due
	 * the lack of hooks in the API (or my understanding thereof)
	 */
	msqlClose(sock);
	sock=-1;
#endif

	return result;
}

char *get_msql_pw(request_rec *r, char *user, msql_auth_config_rec *sec ,char *msql_errstr) {
  	char 		query[MAX_QUERY_LEN];
	char 		esc_user[MAX_FIELD_LEN];

	/* do we have enough information to build a query */
	if (
	    (!sec->auth_msql_pwd_table) ||
	    (!sec->auth_msql_pwd_field) ||
	    (!sec->auth_msql_uname_field)
	   ) {
		sprintf(msql_errstr,
			"mSQL: Missing parameters for password lookup: %s%s%s",
			(sec->auth_msql_pwd_table ? "" : "Password table "),
			(sec->auth_msql_pwd_field ? "" : "Password field name "),
			(sec->auth_msql_uname_field ? "" : "UserID field name ")
			);
		return NULL;
		};

    	if (!(msql_escape(esc_user, user, msql_errstr))) {
		sprintf(msql_errstr,
			"mSQL: Could not cope/escape the '%s' user_id value; ",user);
		return NULL;
    	};
    	sprintf(query,"select %s from %s where %s='%s'",
		sec->auth_msql_pwd_field,
		sec->auth_msql_pwd_table,
		sec->auth_msql_uname_field,
		esc_user
		);

	return do_msql_query(r,query,sec,ONLY_ONCE,msql_errstr);
}

char *get_msql_grp(request_rec *r, char *group,char *user, msql_auth_config_rec *sec, char *msql_errstr) {
  	char 		query[MAX_QUERY_LEN];

	char 		esc_user[MAX_FIELD_LEN];
	char 		esc_group[MAX_FIELD_LEN];

	/* do we have enough information to build a query */
	if (
	    (!sec->auth_msql_grp_table) ||
	    (!sec->auth_msql_grp_field) ||
	    (!sec->auth_msql_uname_field)
	   ) {
		sprintf(msql_errstr,
			"mSQL: Missing parameters for group lookup: %s%s%s",
			(sec->auth_msql_grp_table ? "" : "Group table "),
			(sec->auth_msql_grp_field ? "" : "GroupID field name "),
			(sec->auth_msql_uname_field ? "" : "UserID field name ")
			);
		return NULL;
		};

    	if (!(msql_escape(esc_user, user,msql_errstr))) {
		sprintf(msql_errstr,
			"mSQL: Could not cope/escape the '%s' user_id value",user);

		return NULL;
    	};
    	if (!(msql_escape(esc_group, group,msql_errstr))) {
		sprintf(msql_errstr,
			"mSQL: Could not cope/escape the '%s' group_id value",group);

		return NULL;
    	};

    	sprintf(query,"select %s from %s where %s='%s' and %s='%s'",
		sec->auth_msql_grp_field,
		sec->auth_msql_grp_table,
		sec->auth_msql_uname_field,esc_user,
		sec->auth_msql_grp_field,  esc_group
		);

	return do_msql_query(r,query,sec,0,msql_errstr);
}


int msql_authenticate_basic_user (request_rec *r)
{
    msql_auth_config_rec *sec =
      (msql_auth_config_rec *)get_module_config (r->per_dir_config,
						&msql_auth_module);
    char msql_errstr[MAX_STRING_LEN];
    conn_rec *c = r->connection;
    char *sent_pw, *real_pw;
    int res;
    msql_errstr[0]='\0';

    if ((res = get_basic_auth_pw (r, &sent_pw)))
        return res;

    /* if mSQL *password* checking is configured in any way, i.e. then
     * handle it, if not decline and leave it to the next in line..
     * We do not check on dbase, group, userid or host name, as it is
     * perfectly possible to only do group control with mSQL and leave
     * user control to the next (dbm) guy in line.
     * We no longer check on the user field name; to avoid problems
     * with Backward VITEK.
     */
    if (!sec->auth_msql_pwd_table) return DECLINED;

    if(!(real_pw = get_msql_pw(r, c->user, sec,msql_errstr ))) {
	if ( msql_errstr[0] ) {
		res = SERVER_ERROR;
		} else {
		if (sec->auth_msql_authorative) {
          	   /* insist that the user is in the database
          	    */
          	   sprintf(msql_errstr,"mSQL: Password for user %s not found", c->user);
		   note_basic_auth_failure (r);
		   res = AUTH_REQUIRED;
		   } else {
		   /* pass control on to the next authorization module.
		    */
		   return DECLINED;
		   }; /* if authorative */
               }; /* if no error */
	log_reason (msql_errstr, r->filename, r);
	return res;
    }

    /* allow no password, if the flag is set and the password
     * is empty. But be sure to log this.
     */

    if ((sec->auth_msql_nopasswd) && (!strlen(real_pw))) {
/*
        sprintf(msql_errstr,"mSQL: user %s: Empty/'any' password accepted",c->user);
	log_reason (msql_errstr, r->uri, r);
 */
	return OK;
	};

    /* if the flag is off however, keep that kind of stuff at
     * an arms length.
     */
    if ((!strlen(real_pw)) || (!strlen(sent_pw))) {
        sprintf(msql_errstr,"mSQL: user %s: Empty Password(s) Rejected",c->user);
	log_reason (msql_errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
	};

    if(sec->auth_msql_encrypted) {
        /* anyone know where the prototype for crypt is?
         *
         * PLEASE NOTE:
         *    The crypt function (at least under FreeBSD 2.0.5) returns
         *    a ptr to a *static* array (max 120 chars) and does *not*
         *    modify the string pointed at by sent_pw !
         */
        sent_pw=(char *)crypt(sent_pw,real_pw);
        };

    if (strcmp(real_pw,sent_pw)) {
        sprintf(msql_errstr,"mSQL user %s: password mismatch",c->user);
	log_reason (msql_errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }
    return OK;
}

/* Checking ID */

int msql_check_auth (request_rec *r) {
    int user_result=DECLINED,group_result=DECLINED;

    msql_auth_config_rec *sec =
      (msql_auth_config_rec *)get_module_config (r->per_dir_config,
						&msql_auth_module);
    char msql_errstr[MAX_STRING_LEN];
    char *user = r->connection->user;
    int m = r->method_number;
    array_header *reqs_arr = requires (r);
    require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

    register int x;
    char *t, *w;
    msql_errstr[0]='\0';

    /* If we are not configured, ignore */
    if (!sec->auth_msql_pwd_table) return DECLINED;

    if (!reqs_arr) {
	if (sec->auth_msql_authorative) {
	        sprintf(msql_errstr,"user %s denied, no access rules specified (MSQL-Authorative) ",user);
		log_reason (msql_errstr, r->uri, r);
	        note_basic_auth_failure(r);
		return AUTH_REQUIRED;
		};
	return DECLINED;
 	};

    for(x=0; (x < reqs_arr->nelts) ; x++) {

	if (! (reqs[x].method_mask & (1 << m))) continue;

        t = reqs[x].requirement;
        w = getword(r->pool, &t, ' ');

        if ((user_result != OK) && (!strcmp(w,"user"))) {
	    user_result=AUTH_REQUIRED;
            while(t[0]) {
                w = getword_conf (r->pool, &t);
                if (!strcmp(user,w)) {
                    user_result= OK;
		    break;
		};
            }
	    if ((sec->auth_msql_authorative) && ( user_result != OK)) {
           	sprintf(msql_errstr,"User %s not found (MSQL-Auhtorative)",user);
		log_reason (msql_errstr, r->uri, r);
           	note_basic_auth_failure(r);
		return AUTH_REQUIRED;
		};
        }

        if ( (group_result != OK) && 
	     (!strcmp(w,"group")) &&  
             (sec->auth_msql_grp_table) && 
             (sec->auth_msql_grp_field)
           ) {
	   /* look up the membership for each of the groups in the table
            */
	   group_result=AUTH_REQUIRED;
           while ( (t[0]) && (group_result != OK) && (!msql_errstr[0]) ) {
                if (get_msql_grp(r,getword(r->pool, &t, ' '),user,sec,msql_errstr)) {
			group_result= OK;
			break;
			};
       		};

	   if (msql_errstr[0]) {
	   	log_reason (msql_errstr, r->filename, r);
		return SERVER_ERROR;
		};

	   if ( (sec->auth_msql_authorative) && (group_result != OK) ) {
           	sprintf(msql_errstr,"user %s not in right groups (MSQL-Authorative) ",user);
		log_reason (msql_errstr, r->uri, r);
           	note_basic_auth_failure(r);
		return AUTH_REQUIRED;
		};
           };

        if(!strcmp(w,"valid-user")) {
            user_result= OK;
	    };
        }

    /* Get serious if we are authorative, previous
     * returns are only if msql yielded a correct result. 
     * This really is not needed.
     */
    if (((group_result == AUTH_REQUIRED) || (user_result == AUTH_REQUIRED)) && (sec->auth_msql_authorative) ) {
        sprintf(msql_errstr,"mSQL-Authorative: Access denied on %s %s rule(s) ", 
		(group_result == AUTH_REQUIRED) ? "USER" : "", 
		(user_result == AUTH_REQUIRED) ? "GROUP" : ""
		);
	log_reason (msql_errstr, r->uri, r);
	return AUTH_REQUIRED;
	};

    if ( (user_result == OK) || (group_result == OK))
	return OK;

    return DECLINED;
}


module msql_auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_msql_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   msql_auth_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   msql_authenticate_basic_user,/* check_user_id */
   msql_check_auth,		/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* pre-run fixups */
   NULL				/* logger */
};

