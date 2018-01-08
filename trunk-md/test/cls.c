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

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * Compare a string to a mask
 * Mask characters:
 *   @ - uppercase letter
 *   # - lowercase letter
 *   & - hex digit
 *   # - digit
 *   * - swallow remaining characters
 *  <x> - exact match for any other character
 */
static int checkmask(const char *data, const char *mask)
{
    int i, ch, d;

    for (i = 0; mask[i] != '\0' && mask[i] != '*'; i++) {
        ch = mask[i];
        d = data[i];
        if (ch == '@') {
            if (!isupper(d))
                return 0;
        }
        else if (ch == '$') {
            if (!islower(d))
                return 0;
        }
        else if (ch == '#') {
            if (!isdigit(d))
                return 0;
        }
        else if (ch == '&') {
            if (!isxdigit(d))
                return 0;
        }
        else if (ch != d)
            return 0;
    }

    if (mask[i] == '*')
        return 1;
    else
        return (data[i] == '\0');
}

/*
 * Converts 8 hex digits to a time integer
 */
static int hex2sec(const char *x)
{
    int i, ch;
    unsigned int j;

    for (i = 0, j = 0; i < 8; i++) {
        ch = x[i];
        j <<= 4;
        if (isdigit(ch))
            j |= ch - '0';
        else if (isupper(ch))
            j |= ch - ('A' - 10);
        else
            j |= ch - ('a' - 10);
    }
    if (j == 0xffffffff)
        return -1;  /* so that it works with 8-byte ints */
    else
        return j;
}

int main(int argc, char **argv)
{
    int i, ver;
    DIR *d;
    struct dirent *e;
    const char *s;
    FILE *fp;
    char path[FILENAME_MAX + 1];
    char line[1035];
    time_t date, lmod, expire;
    unsigned int len;
    struct tm ts;
    char sdate[30], slmod[30], sexpire[30];
    const char time_format[] = "%e %b %Y %R";

    if (argc != 2) {
        printf("Usage: cls directory\n");
        exit(0);
    }

    d = opendir(argv[1]);
    if (d == NULL) {
        perror("opendir");
        exit(1);
    }

    for (;;) {
        e = readdir(d);
        if (e == NULL)
            break;
        s = e->d_name;
        if (s[0] == '.' || s[0] == '#')
            continue;
        sprintf(path, "%s/%s", argv[1], s);
        fp = fopen(path, "r");
        if (fp == NULL) {
            perror("fopen");
            continue;
        }
        if (fgets(line, 1034, fp) == NULL) {
            perror("fgets");
            fclose(fp);
            continue;
        }
        if (!checkmask(line, "&&&&&&&& &&&&&&&& &&&&&&&& &&&&&&&& &&&&&&&&\n")) {
            fprintf(stderr, "Bad cache file\n");
            fclose(fp);
            continue;
        }
        date = hex2sec(line);
        lmod = hex2sec(line + 9);
        expire = hex2sec(line + 18);
        ver = hex2sec(line + 27);
        len = hex2sec(line + 35);
        if (fgets(line, 1034, fp) == NULL) {
            perror("fgets");
            fclose(fp);
            continue;
        }
        fclose(fp);
        i = strlen(line);
        if (strncmp(line, "X-URL: ", 7) != 0 || line[i - 1] != '\n') {
            fprintf(stderr, "Bad cache file\n");
            continue;
        }
        line[i - 1] = '\0';
        if (date != -1) {
            ts = *gmtime(&date);
            strftime(sdate, 30, time_format, &ts);
        }
        else
            strcpy(sdate, "-");

        if (lmod != -1) {
            ts = *gmtime(&lmod);
            strftime(slmod, 30, time_format, &ts);
        }
        else
            strcpy(slmod, "-");

        if (expire != -1) {
            ts = *gmtime(&expire);
            strftime(sexpire, 30, time_format, &ts);
        }
        else
            strcpy(sexpire, "-");

        printf("%s: %d; %s  %s  %s\n", line + 7, ver, sdate, slmod, sexpire);
    }

    closedir(d);
    return 0;
}
