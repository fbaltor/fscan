import sys
import argparse

import binwalk


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', help='Path to file to be binwalked')

    args, unkown = parser.parse_known_args(argv)
    print(args.input)
    print(type(args.input))

    binwalk.scan(args.input)

if __name__ == '__main__':
    main(sys.argv)