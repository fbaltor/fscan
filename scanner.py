import argparse
import os
import csv
import tarfile
import tempfile
from multiprocessing import Pool, Manager, cpu_count

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
            else:
                return 'Unknown'

    def save_data(self, processed_data):
        """
        Save the processed data to our data file.
        """
        with open(self.data_file, 'w', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(processed_data)


    def listener(self, queue):
        while True:
            processed_data = queue.get()
            if processed_data == 'kill':
                break

            self.save_data(processed_data)

    def process_single_firmware_image(self, firmware_image_path, queue):
        with tempfile.TemporaryDirectory() as tempdir:
            extractor = Extractor(firmware_image_path, tempdir, kernel=False)
            extractor.extract()

            filesystems = os.listdir(tempdir)
            filesystem = filesystems[0]
            filesystem_path = os.path.join(tempdir, filesystem)
            tar = tarfile.open(filesystem_path)

            firmware = tar.name.split('/')[-1].split('.')[0]
            firmware_web_server_type = self.apply_simple_rule(tar)

            processed_data = [firmware, firmware_web_server_type]

            queue.put(processed_data)

    def run(self):
        manager = Manager()
        queue = manager.Queue()
        pool = Pool(cpu_count() + 2)

        watcher = pool.apply_async(self.listener, (queue,))

        jobs = []
        with os.scandir(self.input_dir) as it:
            for firmware_image in it:
                firmware_path = os.path.abspath(firmware_image.path)
                job = pool.apply_async(self.process_single_firmware_image, (firmware_path, queue))
                jobs.append(job)

        for job in jobs:
            job.get()

        queue.put('kill')
        pool.close()
        pool.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action='store')
    parser.add_argument('--data_file', action='store')
    args = parser.parse_args()

    scanner = Scanner(args.input, args.data_file)
    scanner.run()

if __name__ == '__main__':
    main()