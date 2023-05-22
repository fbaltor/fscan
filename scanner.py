import argparse
import os
import csv
import tempfile
import time
import multiprocessing as mp
import daemonless as dm

from extractor import Extractor
from rules import RuleEvaluator


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

    def save_data(self, processed_data):
        """
        Save the processed data to our data file.
        """

        if not processed_data:
            return

        with open(self.data_file, 'a', newline = '') as f:
            writer = csv.writer(f)
            writer.writerow(processed_data)

    def listener(self):
        global queue

        while True:
            data = queue.get()
            if data == 'kill':
                break

            self.save_data(data)

    def process_single_firmware_image(self, firmware_image_path):
        print(f'Start processing of image {firmware_image_path}')
        with tempfile.TemporaryDirectory() as tempdir:
            extractor = Extractor(firmware_image_path, tempdir, kernel=False)
            extractor.extract()

            filesystems = os.listdir(tempdir)
            if len(filesystems) == 0:
                return
            filesystem = filesystems[0]
            filesystem_path = os.path.join(tempdir, filesystem)

            firmware = filesystem.split('/')[-1].split('.')[0]
            firmware_web_server_type = RuleEvaluator.apply_simple_rule(filesystem_path)
            
            return [firmware, firmware_web_server_type]
        
    def worker(self, firmware_image_path):
        global queue

        data = self.process_single_firmware_image(firmware_image_path)
        queue.put(data)
        return data

    def run(self):
        global queue
        queue = mp.Queue()
        pool = dm.NestablePool(mp.cpu_count() + 2)

        watcher = mp.Process(target = self.listener)
        watcher.start()

        jobs = []
        with os.scandir(self.input_dir) as it:
            for image in it:
                image_path = os.path.abspath(image)
                job = pool.apply_async(self.worker, (image_path,))
                jobs.append(job)
        
        for job in jobs:
            job.get()

        queue.put('kill')
        pool.close()
        pool.join()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action = 'store')
    parser.add_argument('--data_file', action = 'store')
    args = parser.parse_args()

    scanner = Scanner(args.input, args.data_file)
    scanner.run()

if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Elapsed time: {time.time() - start}')
