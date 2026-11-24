#!/usr/bin/env python3
# A MDChallengeDns01 command which records the arguments it was invoked with,
# so that a test can check how mod_md passes them on, and then hands the work
# to dns01.py so that the challenge still succeeds.

import os
import sys

sys.path.append(os.path.dirname(__file__))

import dns01


def main(argv):
    if len(argv) < 4:
        sys.stderr.write(f"{argv[0]} without arguments\n")
        sys.exit(2)
    with open(argv[1], 'a+') as fd:
        fd.write(f'{argv}\n')
    if argv[2] == 'setup':
        if len(argv) != 5:
            sys.stderr.write("wrong number of arguments: "
                             "dns01_record.py <log> setup <domain> <challenge>\n")
            sys.exit(2)
        rv = dns01.setup(argv[3], argv[4])
    elif argv[2] == 'teardown':
        rv = dns01.teardown(argv[3])
    else:
        sys.stderr.write(f"unknown option {argv[2]}\n")
        rv = 2
    sys.exit(rv)


if __name__ == "__main__":
    main(sys.argv)
