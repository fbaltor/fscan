import argparse
import os
import csv
import tarfile
import tempfile
import concurrent.futures as cf

from extractor import Extractor


class Scanner():
    """
    Class that scans a mass of binary firmwares.
    """

    def __init__(self, input_dir, data_file=None):
        self.input_dir = input_dir
        self.data_file = data_file

        if self.data_file is None:
            self.data_file = 'default.csv'
        
        with open(self.data_file, 'w', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(["firmware", "web_server_type"])

    def apply_simple_rule(self, tarfile):
        for file in tarfile.getnames():
            if file.endswith('.php'):
                return 'php'
            if file.endswith('.jcgi'):
                return 'Java CGI'
            if file.endswith('luci'):
                return 'LuCI'
            
        return 'Unknown'

    def save_data(self, processed_data):
        """
        Save the processed data to our data file.
        """

        if not processed_data:
            return

        with open(self.data_file, 'a', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(processed_data)

    def process_single_firmware_image(self, firmware_image_path):
        with tempfile.TemporaryDirectory() as tempdir:
            extractor = Extractor(firmware_image_path, tempdir, kernel=False)
            extractor.extract()

            filesystems = os.listdir(tempdir)
            if len(filesystems) == 0:
                return
            filesystem = filesystems[0]
            filesystem_path = os.path.join(tempdir, filesystem)
            tar = tarfile.open(filesystem_path)

            firmware = tar.name.split('/')[-1].split('.')[0]
            firmware_web_server_type = self.apply_simple_rule(tar)
            
            return [firmware, firmware_web_server_type]

    def run(self):
        with cf.ProcessPoolExecutor() as executor:
            with os.scandir(self.input_dir) as it:
                for firmware_image in it:
                    firmware_path = os.path.abspath(firmware_image.path)
                    future = executor.submit(self.process_single_firmware_image, firmware_path)
                    processed_data = future.result()
                    self.save_data(processed_data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action = 'store')
    parser.add_argument('--data_file', action = 'store')
    args = parser.parse_args()

    scanner = Scanner(args.input, args.data_file)
    scanner.run()

if __name__ == '__main__':
    main()