import argparse
import csv
import os
import shutil
import tarfile
import time
import zipfile
import concurrent.futures as cf

from extractor import Extractor


class MassScanner():
    def __init__(self, input, output = None):
        self.input = os.path.abspath(input)

        if output is None:
            output = 'mass_out'
        self.output = os.path.abspath(output)

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
        with(
            cf.ProcessPoolExecutor() as executor,
            os.scandir(self.input) as images
        ):
            firmware_paths = (os.path.abspath(image.path) for image in images)
            executor.map(self.extract_one, firmware_paths)

    def run(self):
        self.extract_all()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', action = 'store')
    parser.add_argument('--output', '-o', action = 'store')
    args = parser.parse_args()

    scanner = MassScanner(args.input, args.output)
    scanner.run()

if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Elapsed time: {time.time() - start}')