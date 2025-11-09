#!/usr/bin/env python3

import sys


def main(argv):
    if len(argv) > 2:
        with open(argv[1], 'a+') as f1:
            f1.write(f"{argv}\n")
        sys.stderr.write("done, all fine.\n")
        sys.exit(0)
    else:
        sys.stderr.write(f"{argv[0]} without arguments")
        sys.exit(7)
    

if __name__ == "__main__":
    main(sys.argv)
