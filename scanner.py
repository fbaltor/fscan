import argparse
import sqlite3
import os
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

        if data_file is None:
            data_file = 'default.db'
        
        self.con = sqlite3.connect(data_file)
        cursor = self.con.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS filesystem_firmwares" + 
                       "(id INTEGER PRIMARY KEY, firmware TEXT, web_server_type TEXT)")
        self.con.commit()

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
        (tar, firm_web_server_type) = processed_data

        firmware = tar.name.split('/')[-1].split('.')[0]

        save_query = f'INSERT INTO filesystem_firmwares (firmware, web_server_type) VALUES ({firmware}, {firm_web_server_type})'

        cursor = self.con.cursor()
        cursor.execute(save_query)
        self.con.commit()

    def listener(self, queue):
        while True:
            processed_data = queue.get()
            if processed_data == 'kill':
                self.con.close()
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
            firm_web_server_type = self.apply_simple_rule(tar)

            processed_data = (tar, firm_web_server_type)

            queue.put(processed_data)

    def run(self):
        manager = Manager()
        queue = manager.Queue()
        pool = Pool(cpu_count() + 2)

        watcher = pool.apply_async(self.listener, (queue,))

        jobs = []
        with os.scandir(self.input_dir) as it:
            for firmware_image in it:
                job = pool.apply_async(self.process_single_firmware_image, (firmware_image, queue))
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