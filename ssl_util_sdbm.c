/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_util_sdbm.c
**  Built-in Simple DBM
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 *
 * core routines
 */

#include "mod_ssl.h"

#ifdef SSL_USE_SDBM

#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <io.h>
#include <errno.h>
#else
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#ifdef __STDC__
#include <stddef.h>
#endif

#ifndef NULL
#define NULL (void *)0
#endif

/*
 * externals
 */
#ifdef sun
extern int errno;
#endif

/*
 * forward
 */
static int getdbit proto((DBM *, long));
static int setdbit proto((DBM *, long));
static int getpage proto((DBM *, long));
static datum getnext proto((DBM *));
static int makroom proto((DBM *, long, int));

/*
 * useful macros
 */
#define bad(x)          ((x).dptr == NULL || (x).dsize <= 0)
#define exhash(item)    sdbm_hash((item).dptr, (item).dsize)
#define ioerr(db)       ((db)->flags |= DBM_IOERR)

#define OFF_PAG(off)    (long) (off) * PBLKSIZ
#define OFF_DIR(off)    (long) (off) * DBLKSIZ

static long masks[] = {
        000000000000, 000000000001, 000000000003, 000000000007,
        000000000017, 000000000037, 000000000077, 000000000177,
        000000000377, 000000000777, 000000001777, 000000003777,
        000000007777, 000000017777, 000000037777, 000000077777,
        000000177777, 000000377777, 000000777777, 000001777777,
        000003777777, 000007777777, 000017777777, 000037777777,
        000077777777, 000177777777, 000377777777, 000777777777,
        001777777777, 003777777777, 007777777777, 017777777777
};

datum nullitem = {NULL, 0};

DBM *
sdbm_open(file, flags, mode)
register char *file;
register int flags;
register int mode;
{
        register DBM *db;
        register char *dirname;
        register char *pagname;
        register int n;

        if (file == NULL || !*file)
                return errno = EINVAL, (DBM *) NULL;
/*
 * need space for two seperate filenames
 */
        n = strlen(file) * 2 + strlen(DIRFEXT) + strlen(PAGFEXT) + 2;

        if ((dirname = malloc((unsigned) n)) == NULL)
                return errno = ENOMEM, (DBM *) NULL;
/*
 * build the file names
 */
        dirname = strcat(strcpy(dirname, file), DIRFEXT);
        pagname = strcpy(dirname + strlen(dirname) + 1, file);
        pagname = strcat(pagname, PAGFEXT);

        db = sdbm_prep(dirname, pagname, flags, mode);
        free((char *) dirname);
        return db;
}

DBM *
sdbm_prep(dirname, pagname, flags, mode)
char *dirname;
char *pagname;
int flags;
int mode;
{
        register DBM *db;
        struct stat dstat;

        if ((db = (DBM *) malloc(sizeof(DBM))) == NULL)
                return errno = ENOMEM, (DBM *) NULL;

        db->flags = 0;
        db->hmask = 0;
        db->blkptr = 0;
        db->keyptr = 0;
/*
 * adjust user flags so that WRONLY becomes RDWR,
 * as required by this package. Also set our internal
 * flag for RDONLY if needed.
 */
        if (flags & O_WRONLY)
                flags = (flags & ~O_WRONLY) | O_RDWR;
        else if ((flags & 03) == O_RDONLY)
                db->flags = DBM_RDONLY;
#if defined(OS2) || defined(MSDOS) || defined(WIN32)
        flags |= O_BINARY;
#endif

/*
 * open the files in sequence, and stat the dirfile.
 * If we fail anywhere, undo everything, return NULL.
 */
        if ((db->pagf = open(pagname, flags, mode)) > -1) {
                if ((db->dirf = open(dirname, flags, mode)) > -1) {
/*
 * need the dirfile size to establish max bit number.
 */
                        if (fstat(db->dirf, &dstat) == 0) {
/*
 * zero size: either a fresh database, or one with a single,
 * unsplit data page: dirpage is all zeros.
 */
                                db->dirbno = (!dstat.st_size) ? 0 : -1;
                                db->pagbno = -1;
                                db->maxbno = dstat.st_size * BYTESIZ;

                                (void) memset(db->pagbuf, 0, PBLKSIZ);
                                (void) memset(db->dirbuf, 0, DBLKSIZ);
                        /*
                         * success
                         */
                                return db;
                        }
                        (void) close(db->dirf);
                }
                (void) close(db->pagf);
        }
        free((char *) db);
        return (DBM *) NULL;
}

void
sdbm_close(db)
register DBM *db;
{
        if (db == NULL)
                errno = EINVAL;
        else {
                (void) close(db->dirf);
                (void) close(db->pagf);
                free((char *) db);
        }
}

datum
sdbm_fetch(db, key)
register DBM *db;
datum key;
{
        if (db == NULL || bad(key))
                return errno = EINVAL, nullitem;

        if (getpage(db, exhash(key)))
                return getpair(db->pagbuf, key);

        return ioerr(db), nullitem;
}

int
sdbm_delete(db, key)
register DBM *db;
datum key;
{
        if (db == NULL || bad(key))
                return errno = EINVAL, -1;
        if (sdbm_rdonly(db))
                return errno = EPERM, -1;

        if (getpage(db, exhash(key))) {
                if (!delpair(db->pagbuf, key))
                        return -1;
/*
 * update the page file
 */
                if (lseek(db->pagf, OFF_PAG(db->pagbno), SEEK_SET) < 0
                    || write(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                        return ioerr(db), -1;

                return 0;
        }

        return ioerr(db), -1;
}

int
sdbm_store(db, key, val, flags)
register DBM *db;
datum key;
datum val;
int flags;
{
        int need;
        register long hash;

        if (db == NULL || bad(key))
                return errno = EINVAL, -1;
        if (sdbm_rdonly(db))
                return errno = EPERM, -1;

        need = key.dsize + val.dsize;
/*
 * is the pair too big (or too small) for this database ??
 */
        if (need < 0 || need > PAIRMAX)
                return errno = EINVAL, -1;

        if (getpage(db, (hash = exhash(key)))) {
/*
 * if we need to replace, delete the key/data pair
 * first. If it is not there, ignore.
 */
                if (flags == DBM_REPLACE)
                        (void) delpair(db->pagbuf, key);
#ifdef SEEDUPS
                else if (duppair(db->pagbuf, key))
                        return 1;
#endif
/*
 * if we do not have enough room, we have to split.
 */
                if (!fitpair(db->pagbuf, need))
                        if (!makroom(db, hash, need))
                                return ioerr(db), -1;
/*
 * we have enough room or split is successful. insert the key,
 * and update the page file.
 */
                (void) putpair(db->pagbuf, key, val);

                if (lseek(db->pagf, OFF_PAG(db->pagbno), SEEK_SET) < 0
                    || write(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                        return ioerr(db), -1;
        /*
         * success
         */
                return 0;
        }

        return ioerr(db), -1;
}

/*
 * makroom - make room by splitting the overfull page
 * this routine will attempt to make room for SPLTMAX times before
 * giving up.
 */
static int
makroom(db, hash, need)
register DBM *db;
long hash;
int need;
{
        long newp;
        char twin[PBLKSIZ];
        char *pag = db->pagbuf;
        char *new = twin;
        register int smax = SPLTMAX;

        do {
/*
 * split the current page
 */
                (void) splpage(pag, new, db->hmask + 1);
/*
 * address of the new page
 */
                newp = (hash & db->hmask) | (db->hmask + 1);

/*
 * write delay, read avoidence/cache shuffle:
 * select the page for incoming pair: if key is to go to the new page,
 * write out the previous one, and copy the new one over, thus making
 * it the current page. If not, simply write the new page, and we are
 * still looking at the page of interest. current page is not updated
 * here, as sdbm_store will do so, after it inserts the incoming pair.
 */
                if (hash & (db->hmask + 1)) {
                        if (lseek(db->pagf, OFF_PAG(db->pagbno), SEEK_SET) < 0
                            || write(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                                return 0;
                        db->pagbno = newp;
                        (void) memcpy(pag, new, PBLKSIZ);
                }
                else if (lseek(db->pagf, OFF_PAG(newp), SEEK_SET) < 0
                         || write(db->pagf, new, PBLKSIZ) < 0)
                        return 0;

                if (!setdbit(db, db->curbit))
                        return 0;
/*
 * see if we have enough room now
 */
                if (fitpair(pag, need))
                        return 1;
/*
 * try again... update curbit and hmask as getpage would have
 * done. because of our update of the current page, we do not
 * need to read in anything. BUT we have to write the current
 * [deferred] page out, as the window of failure is too great.
 */
                db->curbit = 2 * db->curbit +
                        ((hash & (db->hmask + 1)) ? 2 : 1);
                db->hmask |= db->hmask + 1;

                if (lseek(db->pagf, OFF_PAG(db->pagbno), SEEK_SET) < 0
                    || write(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                        return 0;

        } while (--smax);
/*
 * if we are here, this is real bad news. After SPLTMAX splits,
 * we still cannot fit the key. say goodnight.
 */
#ifdef BADMESS
        (void) write(2, "sdbm: cannot insert after SPLTMAX attempts.\n", 44);
#endif
        return 0;

}

/*
 * the following two routines will break if
 * deletions aren't taken into account. (ndbm bug)
 */
datum
sdbm_firstkey(db)
register DBM *db;
{
        if (db == NULL)
                return errno = EINVAL, nullitem;
/*
 * start at page 0
 */
        if (lseek(db->pagf, OFF_PAG(0), SEEK_SET) < 0
            || read(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                return ioerr(db), nullitem;
        db->pagbno = 0;
        db->blkptr = 0;
        db->keyptr = 0;

        return getnext(db);
}

datum
sdbm_nextkey(db)
register DBM *db;
{
        if (db == NULL)
                return errno = EINVAL, nullitem;
        return getnext(db);
}

/*
 * all important binary trie traversal
 */
static int
getpage(db, hash)
register DBM *db;
register long hash;
{
        register int hbit;
        register long dbit;
        register long pagb;

        dbit = 0;
        hbit = 0;
        while (dbit < db->maxbno && getdbit(db, dbit))
                dbit = 2 * dbit + ((hash & (1 << hbit++)) ? 2 : 1);

        debug(("dbit: %d...", dbit));

        db->curbit = dbit;
        db->hmask = masks[hbit];

        pagb = hash & db->hmask;
/*
 * see if the block we need is already in memory.
 * note: this lookaside cache has about 10% hit rate.
 */
        if (pagb != db->pagbno) {
/*
 * note: here, we assume a "hole" is read as 0s.
 * if not, must zero pagbuf first.
 */
                if (lseek(db->pagf, OFF_PAG(pagb), SEEK_SET) < 0
                    || read(db->pagf, db->pagbuf, PBLKSIZ) < 0)
                        return 0;
                if (!chkpage(db->pagbuf))
                        return 0;
                db->pagbno = pagb;

                debug(("pag read: %d\n", pagb));
        }
        return 1;
}

static int
getdbit(db, dbit)
register DBM *db;
register long dbit;
{
        register long c;
        register long dirb;

        c = dbit / BYTESIZ;
        dirb = c / DBLKSIZ;

        if (dirb != db->dirbno) {
                if (lseek(db->dirf, OFF_DIR(dirb), SEEK_SET) < 0
                    || read(db->dirf, db->dirbuf, DBLKSIZ) < 0)
                        return 0;
                db->dirbno = dirb;

                debug(("dir read: %d\n", dirb));
        }

        return db->dirbuf[c % DBLKSIZ] & (1 << dbit % BYTESIZ);
}

static int
setdbit(db, dbit)
register DBM *db;
register long dbit;
{
        register long c;
        register long dirb;

        c = dbit / BYTESIZ;
        dirb = c / DBLKSIZ;

        if (dirb != db->dirbno) {
                if (lseek(db->dirf, OFF_DIR(dirb), SEEK_SET) < 0
                    || read(db->dirf, db->dirbuf, DBLKSIZ) < 0)
                        return 0;
                db->dirbno = dirb;

                debug(("dir read: %d\n", dirb));
        }

        db->dirbuf[c % DBLKSIZ] |= (1 << dbit % BYTESIZ);

        if (dbit >= db->maxbno)
                db->maxbno += DBLKSIZ * BYTESIZ;

        if (lseek(db->dirf, OFF_DIR(dirb), SEEK_SET) < 0
            || write(db->dirf, db->dirbuf, DBLKSIZ) < 0)
                return 0;

        return 1;
}

/*
 * getnext - get the next key in the page, and if done with
 * the page, try the next page in sequence
 */
static datum
getnext(db)
register DBM *db;
{
        datum key;

        for (;;) {
                db->keyptr++;
                key = getnkey(db->pagbuf, db->keyptr);
                if (key.dptr != NULL)
                        return key;
/*
 * we either run out, or there is nothing on this page..
 * try the next one... If we lost our position on the
 * file, we will have to seek.
 */
                db->keyptr = 0;
                if (db->pagbno != db->blkptr++)
                        if (lseek(db->pagf, OFF_PAG(db->blkptr), SEEK_SET) < 0)
                                break;
                db->pagbno = db->blkptr;
                if (read(db->pagf, db->pagbuf, PBLKSIZ) <= 0)
                        break;
                if (!chkpage(db->pagbuf))
                        break;
        }

        return ioerr(db), nullitem;
}

/* ************************* */

/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain. keep it that way.
 *
 * hashing routine
 */

/*
 * polynomial conversion ignoring overflows
 * [this seems to work remarkably well, in fact better
 * then the ndbm hash function. Replace at your own risk]
 * use: 65599   nice.
 *      65587   even better.
 */
long
sdbm_hash(str, len)
register char *str;
register int len;
{
        register unsigned long n = 0;

#ifdef DUFF
#define HASHC   n = *str++ + 65599 * n
        if (len > 0) {
                register int loop = (len + 8 - 1) >> 3;

                switch(len & (8 - 1)) {
                case 0: do {
                        HASHC;  case 7: HASHC;
                case 6: HASHC;  case 5: HASHC;
                case 4: HASHC;  case 3: HASHC;
                case 2: HASHC;  case 1: HASHC;
                        } while (--loop);
                }

        }
#else
        while (len--)
                n = *str++ + 65599 * n;
#endif
        return n;
}

/* ************************* */

/*
 * sdbm - ndbm work-alike hashed database library
 * based on Per-Aake Larson's Dynamic Hashing algorithms. BIT 18 (1978).
 * author: oz@nexus.yorku.ca
 * status: public domain.
 *
 * page-level routines
 */

#define exhash(item)    sdbm_hash((item).dptr, (item).dsize)

/*
 * forward
 */
static int seepair proto((char *, int, char *, int));

/*
 * page format:
 *      +------------------------------+
 * ino  | n | keyoff | datoff | keyoff |
 *      +------------+--------+--------+
 *      | datoff | - - - ---->         |
 *      +--------+---------------------+
 *      |        F R E E A R E A       |
 *      +--------------+---------------+
 *      |  <---- - - - | data          |
 *      +--------+-----+----+----------+
 *      |  key   | data     | key      |
 *      +--------+----------+----------+
 *
 * calculating the offsets for free area:  if the number
 * of entries (ino[0]) is zero, the offset to the END of
 * the free area is the block size. Otherwise, it is the
 * nth (ino[ino[0]]) entry's offset.
 */

int
fitpair(pag, need)
char *pag;
int need;
{
        register int n;
        register int off;
        register int avail;
        register short *ino = (short *) pag;

        off = ((n = ino[0]) > 0) ? ino[n] : PBLKSIZ;
        avail = off - (n + 1) * sizeof(short);
        need += 2 * sizeof(short);

        debug(("free %d need %d\n", avail, need));

        return need <= avail;
}

void
putpair(pag, key, val)
char *pag;
datum key;
datum val;
{
        register int n;
        register int off;
        register short *ino = (short *) pag;

        off = ((n = ino[0]) > 0) ? ino[n] : PBLKSIZ;
/*
 * enter the key first
 */
        off -= key.dsize;
        (void) memcpy(pag + off, key.dptr, key.dsize);
        ino[n + 1] = off;
/*
 * now the data
 */
        off -= val.dsize;
        (void) memcpy(pag + off, val.dptr, val.dsize);
        ino[n + 2] = off;
/*
 * adjust item count
 */
        ino[0] += 2;
}

datum
getpair(pag, key)
char *pag;
datum key;
{
        register int i;
        register int n;
        datum val;
        register short *ino = (short *) pag;

        if ((n = ino[0]) == 0)
                return nullitem;

        if ((i = seepair(pag, n, key.dptr, key.dsize)) == 0)
                return nullitem;

        val.dptr = pag + ino[i + 1];
        val.dsize = ino[i] - ino[i + 1];
        return val;
}

#ifdef SEEDUPS
int
duppair(pag, key)
char *pag;
datum key;
{
        register short *ino = (short *) pag;
        return ino[0] > 0 && seepair(pag, ino[0], key.dptr, key.dsize) > 0;
}
#endif

datum
getnkey(pag, num)
char *pag;
int num;
{
        datum key;
        register int off;
        register short *ino = (short *) pag;

        num = num * 2 - 1;
        if (ino[0] == 0 || num > ino[0])
                return nullitem;

        off = (num > 1) ? ino[num - 1] : PBLKSIZ;

        key.dptr = pag + ino[num];
        key.dsize = off - ino[num];

        return key;
}

int
delpair(pag, key)
char *pag;
datum key;
{
        register int n;
        register int i;
        register short *ino = (short *) pag;

        if ((n = ino[0]) == 0)
                return 0;

        if ((i = seepair(pag, n, key.dptr, key.dsize)) == 0)
                return 0;
/*
 * found the key. if it is the last entry
 * [i.e. i == n - 1] we just adjust the entry count.
 * hard case: move all data down onto the deleted pair,
 * shift offsets onto deleted offsets, and adjust them.
 * [note: 0 < i < n]
 */
        if (i < n - 1) {
                register int m;
                register char *dst = pag + (i == 1 ? PBLKSIZ : ino[i - 1]);
                register char *src = pag + ino[i + 1];
                register int   zoo = dst - src;

                debug(("free-up %d ", zoo));
/*
 * shift data/keys down
 */
                m = ino[i + 1] - ino[n];
#ifdef DUFF
#define MOVB    *--dst = *--src
                if (m > 0) {
                        register int loop = (m + 8 - 1) >> 3;

                        switch (m & (8 - 1)) {
                        case 0: do {
                                MOVB;   case 7: MOVB;
                        case 6: MOVB;   case 5: MOVB;
                        case 4: MOVB;   case 3: MOVB;
                        case 2: MOVB;   case 1: MOVB;
                                } while (--loop);
                        }
                }
#else
                dst -= m;
                src -= m;
                memmove(dst, src, m);
#endif
/*
 * adjust offset index up
 */
                while (i < n - 1) {
                        ino[i] = ino[i + 2] + zoo;
                        i++;
                }
        }
        ino[0] -= 2;
        return 1;
}

/*
 * search for the key in the page.
 * return offset index in the range 0 < i < n.
 * return 0 if not found.
 */
static int
seepair(pag, n, key, siz)
char *pag;
register int n;
register char *key;
register int siz;
{
        register int i;
        register int off = PBLKSIZ;
        register short *ino = (short *) pag;

        for (i = 1; i < n; i += 2) {
                if (siz == off - ino[i] &&
                    memcmp(key, pag + ino[i], siz) == 0)
                        return i;
                off = ino[i + 1];
        }
        return 0;
}

void
splpage(pag, new, sbit)
char *pag;
char *new;
long sbit;
{
        datum key;
        datum val;

        register int n;
        register int off = PBLKSIZ;
        char cur[PBLKSIZ];
        register short *ino = (short *) cur;

        (void) memcpy(cur, pag, PBLKSIZ);
        (void) memset(pag, 0, PBLKSIZ);
        (void) memset(new, 0, PBLKSIZ);

        n = ino[0];
        for (ino++; n > 0; ino += 2) {
                key.dptr = cur + ino[0];
                key.dsize = off - ino[0];
                val.dptr = cur + ino[1];
                val.dsize = ino[0] - ino[1];
/*
 * select the page pointer (by looking at sbit) and insert
 */
                (void) putpair((exhash(key) & sbit) ? new : pag, key, val);

                off = ino[1];
                n -= 2;
        }

        debug(("%d split %d/%d\n", ((short *) cur)[0] / 2,
               ((short *) new)[0] / 2,
               ((short *) pag)[0] / 2));
}

/*
 * check page sanity:
 * number of entries should be something
 * reasonable, and all offsets in the index should be in order.
 * this could be made more rigorous.
 */
int
chkpage(pag)
char *pag;
{
        register int n;
        register int off;
        register short *ino = (short *) pag;

        if ((n = ino[0]) < 0 || n > PBLKSIZ / sizeof(short))
                return 0;

        if (n > 0) {
                off = PBLKSIZ;
                for (ino++; n > 0; ino += 2) {
                        if (ino[0] > off || ino[1] > off ||
                            ino[1] > ino[0])
                                return 0;
                        off = ino[1];
                        n -= 2;
                }
        }
        return 1;
}

#endif /* SSL_USE_SDBM */
