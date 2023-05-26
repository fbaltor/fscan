import argparse
import subprocess as sp
import os
import tarfile
import tempfile

from helpers import which


class SAST():

    @staticmethod
    def _run_semgrep(firmware_filesystem_directory_path):
        semgrep_exec = which('semgrep')

        semgrep_output_file = tempfile.NamedTemporaryFile()

        result = sp.run(
            [semgrep_exec, '--config=auto', firmware_filesystem_directory_path, '--verbose', '--json'],
            capture_output = True,
            text = True
        )

        if result.returncode != 0:
            print('Error when running semgrep, returning...')
            return
        
        return result

    @staticmethod
    def run_semgrep(firmware_filesystem_path):
        if os.path.isdir(firmware_filesystem_path):
            return SAST._run_semgrep(firmware_filesystem_path)

        if tarfile.is_tarfile(firmware_filesystem_path):
            with tarfile.open(firmware_filesystem_path) as tf:
                extract_dir = os.path.dirname(firmware_filesystem_path)
                extract_dir = os.path.join(extract_dir, 'extract')
                tf.extractall(path = extract_dir)

                return SAST._run_semgrep(extract_dir)
            
        return SAST._run_semgrep(firmware_filesystem_path)

    @staticmethod
    def extract_rules(firmware_filesystem_path, output_rules_path):
        result = SAST.run_semgrep(firmware_filesystem_path)
        print(result)
        print(result.stdout)
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--output', '-o', action = 'store')
    parser.add_argument('--extract-rules', '-e', dest = 'extract_rules', action = 'store_true')
    args = parser.parse_args()

    if args.extract_rules:
        return SAST.extract_rules(args.input, args.output)


if __name__ == '__main__':
    main()