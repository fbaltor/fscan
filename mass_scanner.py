import argparse
import csv
import os
import shutil
import tarfile
import time
import zipfile
import concurrent.futures as cf

from extractor import Extractor
from rules import RuleEvaluator


SCAN_FILE_NAME = 'scan_result.csv'

class MassScanner():
    def __init__(self, input = None, output = None, evaluate_rules = None):
        if output is None:
            output = 'mass_out'
        self.output = os.path.abspath(output)

        if evaluate_rules:
            self.scan = os.path.join(self.output, SCAN_FILE_NAME)
            return

        self._initialize_clean_output_dir()

        if input:
            self.input = os.path.abspath(input)

    def _initialize_clean_output_dir(self):
        if os.path.isdir(self.output):
            shutil.rmtree(self.output)

        os.mkdir(self.output)

        SCAN_FILE_NAME = 'scan_result.csv'
        self.scan = os.path.join(self.output, SCAN_FILE_NAME)

        with open(self.scan, 'w', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(['firmware', 'web_server_type'])

    def extract_one(self, firmware_path):
        output_dir = os.path.join(self.output, self._get_firmware_name(firmware_path))
        os.mkdir(output_dir)
        os.chdir(output_dir)

        extractor = Extractor(firmware_path, outdir = output_dir, kernel = False)
        extractor.extract()

        filesystems = os.listdir(output_dir)
        if len(filesystems) == 0:
            return
        filesystem = filesystems[0]
        filesystem = os.path.abspath(filesystem)

        if not tarfile.is_tarfile(filesystem):
            return
        
        with tarfile.open(filesystem) as tf:
            tf.extractall()

        os.remove(filesystem)

    def _get_firmware_name(self, firmware_path):
        with zipfile.ZipFile(firmware_path) as zf:
            top = {item.split('/')[0] for item in zf.namelist()}
            name = top.pop()
            name = name.replace(' ', '_')

            return name

    def extract_all(self):
        with (
            cf.ProcessPoolExecutor() as executor,
            os.scandir(self.input) as images
        ):

            firmware_paths = [os.path.abspath(image.path) for image in images if image.path != os.path.abspath(self.output)]
            executor.map(self.extract_one, firmware_paths)

    def evaluate_rule_in_one(self, filesystem_path):
        firmware_web_server_type = RuleEvaluator.apply_simple_rule(filesystem_path)
        firmware = os.path.basename(filesystem_path)

        data = [firmware, firmware_web_server_type]
        
        with open(self.scan, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(data)

    def _filesystem_is_valid(self, filesystem):
        if os.path.isfile(filesystem):
            return False
        
        if len(os.listdir(filesystem)) == 0:
            return False

        return True

    def evaluate_rules_all(self):
        with (
            cf.ProcessPoolExecutor() as executor,
            os.scandir(self.output) as filesystems
        ):
            filesystem_paths = (filesystem.path for filesystem in filesystems if self._filesystem_is_valid(filesystem.path))
            executor.map(self.evaluate_rule_in_one, filesystem_paths)

    def run(self):
        self.extract_all()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--output', '-o', action = 'store')
    parser.add_argument('--extract', '-e', action = 'store_true')
    parser.add_argument('--evaluate-rules', '-r', dest = 'evaluate', action = 'store_true')
    args = parser.parse_args()

    if args.extract:
        scanner = MassScanner(input = args.input, output = args.output)
        scanner.extract_all()
        return

    if args.evaluate:
        scanner = MassScanner(output = args.output, evaluate_rules = args.evaluate)
        scanner.evaluate_rules_all()
        return
    
    scanner = MassScanner(input = args.input, output = args.output)
    scanner.extract_all()
    scanner.evaluate_rules_all()

if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Elapsed time: {time.time() - start}')
