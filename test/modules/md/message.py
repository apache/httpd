#!/usr/bin/env python3

import os
import sys


def main(argv):
    if len(argv) > 2:
        cmd = argv[2]
        if 'renewing' != cmd:
            f1 = open(argv[1], 'a+')
            f1.write(f'{argv}\n')
            if 'MD_VERSION' in os.environ:
                f1.write(f'MD_VERSION={os.environ["MD_VERSION"]}\n')
            if 'MD_STORE' in os.environ:
                f1.write(f'MD_STORE={os.environ["MD_STORE"]}\n')
            f1.close()
        sys.stderr.write("done, all fine.\n")
        sys.exit(0)
    else:
        sys.stderr.write(f"{argv[0]} without arguments")
        sys.exit(7)
    

if __name__ == "__main__":
    main(sys.argv)
