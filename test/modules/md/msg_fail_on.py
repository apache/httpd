#!/usr/bin/env python3

import os
import sys


def main(argv):
    if len(argv) > 3:
        log = argv[1]
        fail_on = argv[2]
        cmd = argv[3]
        domain = argv[4]
        if 'renewing' != cmd:
            f1 = open(log, 'a+')
            f1.write(f"{[argv[0], log, cmd, domain]}\n")
            f1.close()
        if cmd.startswith(fail_on):
            sys.stderr.write(f"failing on: {cmd}\n")
            sys.exit(1)
        sys.stderr.write("done, all fine.\n")
        sys.exit(0)
    else:
        sys.stderr.write("%s without arguments" % (argv[0]))
        sys.exit(7)


if __name__ == "__main__":
    main(sys.argv)
