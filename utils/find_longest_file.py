import argparse
import os

def buf_count_newlines_gen(fname):
    def _make_gen(reader):
        while True:
            b = reader(2 ** 16)
            if not b: break
            yield b

    with open(fname, "rb") as f:
        count = sum(buf.count(b"\n") for buf in _make_gen(f.raw.read))
    return count

def compare_files(input_directory):
    base = os.path.abspath(input_directory)
    files = os.listdir(input_directory)
    files = [os.path.join(base, f) for f in files]
    files = [f for f in files if os.path.isfile(f)]
    files = [(f, buf_count_newlines_gen(f)) for f in files]
    files = sorted(files, key = lambda el: el[1], reverse = True)
    files = [(os.path.basename(f[0]), f[1]) for f in files]

    print(*files, sep = '\n')


def main():
    parser  = argparse.ArgumentParser()
    parser.add_argument('input_directory', action = 'store')
    args = parser.parse_args()
    print(args)

    compare_files(args.input_directory)

if __name__ == '__main__':
    main()
