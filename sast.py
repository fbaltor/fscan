import argparse
import subprocess as sp
import os
import csv
import json
import tarfile
import tempfile

from helpers import which


class SAST():

    @staticmethod
    def _run_semgrep(firmware_filesystem_directory_path, output_file):
        semgrep_exec = which('semgrep')

        result = sp.run(
            [semgrep_exec, '--config=auto', firmware_filesystem_directory_path, '--no-git-ignore', '--json', '--output', output_file],
            capture_output= True,
            text = True
        )

        if result.returncode != 0:
            print('Error when running semgrep, returning...')
            return
        
        return result

    @staticmethod
    def run_semgrep(firmware_filesystem_path, output_file):
        if os.path.isdir(firmware_filesystem_path):
            return SAST._run_semgrep(firmware_filesystem_path, output_file)

        if tarfile.is_tarfile(firmware_filesystem_path):
            with tarfile.open(firmware_filesystem_path) as tf:
                extract_dir = os.path.dirname(firmware_filesystem_path)
                extract_dir = os.path.join(extract_dir, 'extract')
                tf.extractall(path = extract_dir)

                return SAST._run_semgrep(extract_dir, output_file)
            
        return SAST._run_semgrep(firmware_filesystem_path, output_file)

    @staticmethod
    def extract_rules(firmware_filesystem_path, output_rules_path):
        with tempfile.NamedTemporaryFile() as tf:
            SAST.run_semgrep(firmware_filesystem_path, tf.name)

            with open(tf.name) as r:
                semgrep_json = json.load(r)
                results = semgrep_json['results']
                rule_check_id_list = [result['check_id'] for result in results]

            with open(output_rules_path, 'w') as w:
                for rule in rule_check_id_list:
                    w.write(f'{rule}\n')
        
        return rule_check_id_list
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--output', '-o', action = 'store')
    parser.add_argument('--extract-rules', '-e', dest = 'extract_rules', action = 'store_true')
    args = parser.parse_args()

    if args.extract_rules:
        return SAST.extract_rules(os.path.abspath(args.input), os.path.abspath(args.output))


if __name__ == '__main__':
    main()