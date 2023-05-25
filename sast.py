import subprocess as sp
import os
import tarfile

from helpers import which


class SAST():

    @staticmethod
    def run_semgrep(firmware_filesystem_path, semgrep_result_path):
        with tarfile.open(firmware_filesystem_path) as tf:
            extract_dir = os.path.dirname(firmware_filesystem_path)
            extract_dir = os.path.join(extract_dir, 'extract')
            tf.extractall(path = extract_dir)

            semgrep_exec = which('semgrep')

            result = sp.run(
                [semgrep_exec, '--config=auto', extract_dir, '--verbose'],
                capture_output = True,
                text = True)

            if result.returncode != 0:
                print("Error when running semgrep, returning...")
                return
            
            with open(semgrep_result_path, 'w') as f:
                f.write(result.stdout)