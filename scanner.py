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

    def save_data(self, data):
        """
        Save the processed data to our data file.
        """
        pass

    def apply_simple_rule(self, tarfile):
        for file in tarfile.getnames():
            if file.endswith('.php'):
                return 'php'
            
        pass

    def process_single_firmware_image(self, firmware_image_path):
        with tempfile.TemporaryDirectory() as tempdir:
            extractor = Extractor(firmware_image_path, tempdir, kernel=False)
            extractor.extract()

            filesystems = os.listdir(tempdir)
            filesystem = filesystems[0]
            filesystem_path = os.path.join(tempdir, filesystem)

            tar = tarfile.open(filesystem_path)

            result = self.apply_simple_rule(tar)



    def listener(self, queue):
        while True:
            processed_data = queue.get()
            if processed_data == 'kill':
                self.con.close()
                break

            self.save_data(processed_data)
    

    def run(self):
        manager = Manager()
        queue = manager.Queue()
        pool = Pool(cpu_count() + 2)

        watcher = pool.apply_async(self.listener, (queue,))


        processes = []
        with os.scandir(self.input_dir) as it:
            for firmware_image in it:
                pass

    

def main():
    pass