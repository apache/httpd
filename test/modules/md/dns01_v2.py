#!/usr/bin/env python3

import subprocess
import sys

curl = "curl"
challtestsrv = "localhost:8055"


def run(args):
    sys.stderr.write(f"run: {' '.join(args)}\n")
    p = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errput = p.communicate(None)
    rv = p.wait()
    if rv != 0:
        sys.stderr.write(errput.decode())
    sys.stdout.write(output.decode())
    return rv


def teardown(domain):
    rv = run([curl, '-s', '-d', f'{{"host":"_acme-challenge.{domain}"}}',
              f'{challtestsrv}/clear-txt'])
    if rv == 0:
        rv = run([curl, '-s', '-d', f'{{"host":"{domain}"}}',
                  f'{challtestsrv}/set-txt'])
    return rv


def setup(domain, challenge):
    teardown(domain)
    rv = run([curl, '-s', '-d', f'{{"host":"{domain}", "addresses":["127.0.0.1"]}}',
              f'{challtestsrv}/set-txt'])
    if rv == 0:
        rv = run([curl, '-s', '-d', f'{{"host":"_acme-challenge.{domain}.", "value":"{challenge}"}}',
                  f'{challtestsrv}/set-txt'])
    return rv


def main(argv):
    if len(argv) > 1:
        if argv[1] == 'setup':
            if len(argv) != 4:
                sys.stderr.write("wrong number of arguments: dns01.py setup <domain> <challenge>\n")
                sys.exit(2)
            rv = setup(argv[2], argv[3])
        elif argv[1] == 'teardown':
            if len(argv) != 4:
                sys.stderr.write("wrong number of arguments: dns01.py teardown <domain> <challenge>\n")
                sys.exit(1)
            rv = teardown(argv[2])
        else:
            sys.stderr.write(f"unknown option {argv[1]}\n")
            rv = 2
    else:
        sys.stderr.write("dns01.py wrong number of arguments\n")
        rv = 2
    sys.exit(rv)


if __name__ == "__main__":
    main(sys.argv)
