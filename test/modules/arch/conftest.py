import sys

# Subdirectories here are named for the platform whose interfaces they
# test, and are not collected anywhere else.
collect_ignore = [] if sys.platform.startswith('linux') else ['linux']
