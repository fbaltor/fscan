import argparse
import subprocess as sp
import os
import json
import tarfile
import tempfile

import httpx
import anyio

from helpers import which


class SAST():

    @staticmethod
    def _run_semgrep(firmware_filesystem_directory_path):
        semgrep_exec = which('semgrep')

        with tempfile.NamedTemporaryFile() as tf:
            result = sp.run(
                [
                    semgrep_exec,
                    '--config=auto',
                    firmware_filesystem_directory_path,
                    '--no-git-ignore',
                    '--json',
                    '--output',
                    tf.name
                ],
                capture_output= True,
                text = True
            )

            if result.returncode != 0:
                print('Error when running semgrep, returning...')
                return

            with open(tf.name) as r:
                return json.load(r)

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
    def extract_rules(firmware_filesystem_path, should_output = False):
        semgrep_json = SAST.run_semgrep(firmware_filesystem_path)
        results = semgrep_json['results']
        rule_check_id_list = [result['check_id'] for result in results]
        rule_check_id_list = list(set(rule_check_id_list))

        if should_output:
            print(rule_check_id_list)

        return rule_check_id_list
    
    @staticmethod
    def _format_rule_check_id_to_url(rule_check_id):
        rule_parts = rule_check_id.split('.')[:-1]
        url = '/'.join(rule_parts) + '.yaml'

        return url

    list_sample = ['generic.secrets.security.detected-private-key.detected-private-key',
                'php.lang.security.unlink-use.unlink-use']
    
    @staticmethod
    async def download_rules(rule_check_id_list = list_sample):
        github_raw_url = 'https://raw.githubusercontent.com/returntocorp/semgrep-rules/develop/'
                
        async with httpx.AsyncClient() as client:
            for rule_check_id in rule_check_id_list:
                url = github_raw_url + SAST._format_rule_check_id_to_url(rule_check_id)
                response = await client.get(url)
                print(response.content)
        
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--extract-rules', '-e', dest = 'extract_rules', action = 'store_true')
    parser.add_argument('--download', '-d', dest = 'download', action = 'store_true')
    args = parser.parse_args()

    if args.extract_rules:
        return SAST.extract_rules(os.path.abspath(args.input), should_output = True)
    elif args.download:
        anyio.run(SAST.download_rules)

if __name__ == '__main__':
    main()