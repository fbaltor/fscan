Simple tool to scan firmware images and generate metrics about their file system.

To install, create a virtual environment and run:
```bash
$ pip install -r requirements.txt
```

To run the complete scan pipeline (as of today, Semgrep + server binary type analysis), run:
```bash
$ python3 scanner.py --input input_folder_with_firmware_images --output output_result_folder
```