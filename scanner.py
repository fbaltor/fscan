import argparse
import os
import csv
import tempfile
import time
import shutil
import concurrent.futures as cf

from extractor import Extractor
from rules import RuleEvaluator
from sast import SAST


class Scanner():
    """
    Class that scans a mass of binary firmwares.
    """

    def __init__(self, input, output = None):
        self.input = input
        self._initialize_output_dir(output)
        

    def _initialize_output_dir(self, output):
        if output is None:
            output = 'out'
        self.output = os.path.abspath(output)

        if os.path.isdir(self.output):
            shutil.rmtree(self.output)

        os.mkdir(self.output)

        SCAN_FILE_NAME = 'scan_result.csv'
        self.scan = os.path.join(self.output, SCAN_FILE_NAME)

        with open(self.scan, 'w', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(["firmware", "web_server_type"])

    def save_webserver_bin_data(self, data):
        if not data:
            return

        with open(self.scan, 'a', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(data)

    def save_sast_data(self, data):
        if not data:
            return
        
        semgrep_result_path = os.path.join(self.output, f'{self.current_firmware_hash}_semgrep.txt')
        with open(semgrep_result_path, 'w') as f:
                f.write(data.stdout)

    def process_single_firmware_image(self, firmware_image_path):
        with tempfile.TemporaryDirectory() as tempdir:
            extractor = Extractor(firmware_image_path, tempdir, kernel=False)
            extractor.extract()

            filesystems = os.listdir(tempdir)
            if len(filesystems) == 0:
                return
            
            filesystem = filesystems[0] # Get the first filesystem
            filesystem_full_path = os.path.join(tempdir, filesystem)
            self.current_firmware_hash = filesystem.split('/')[-1].split('.')[0]

            sast_data = SAST.run_semgrep(filesystem_full_path)
            self.save_sast_data(sast_data)

            run_rules = True
            firmware_web_server_type = RuleEvaluator.apply_simple_rule(filesystem_full_path) if run_rules else 'Unknown'
            
            return [self.current_firmware_hash, firmware_web_server_type]

    def run(self):
        with (
            cf.ProcessPoolExecutor() as executor,
            os.scandir(self.input) as images
        ):
            firmware_paths = (os.path.abspath(img.path) for img in images)
            processed_paths = executor.map(self.process_single_firmware_image, firmware_paths)

            for data in processed_paths:
                self.save_webserver_bin_data(data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--output', '-o', action = 'store')
    args = parser.parse_args()

    scanner = Scanner(args.input, args.output)
    scanner.run()

if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Elapsed time: {time.time() - start}')
