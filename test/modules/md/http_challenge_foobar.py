#!/usr/bin/env python3
import os
import re
import sys


def main(argv):
    if len(argv) < 4:
        sys.stderr.write(f"{argv[0]} without too few arguments")
        sys.exit(7)
    store_dir = argv[1]
    event = argv[2]
    mdomain = argv[3]
    m = re.match(r'(\S+):(\S+):(\S+)', event)
    if m and 'challenge-setup' == m.group(1) and 'http-01' == m.group(2):
        dns_name = m.group(3)
        challenge_file = f"{store_dir}/challenges/{dns_name}/acme-http-01.txt"
        if not os.path.isfile(challenge_file):
            sys.stderr.write(f"{argv[0]} does not exist: {challenge_file}")
            sys.exit(8)
        with open(challenge_file, 'w') as fd:
            fd.write('this_is_an_invalidated_http-01_challenge')
    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv)
