#!/usr/bin/env python3

import sys


def main(argv):
    if len(argv) > 1:
        msg = argv[2] if len(argv) > 2 else None
        # fail on later messaging stages, not the initial 'renewing' one.
        # we have test_901_030 that check that later stages are not invoked
        # when misconfigurations are detected early.
        sys.exit(1 if msg != "renewing" else 0)
    

if __name__ == "__main__":
    main(sys.argv)
