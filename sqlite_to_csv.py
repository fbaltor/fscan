import sqlite3
import csv


DATA_FILE = 'default.db'
TABLE = 'filesystem_firmwares'

con = sqlite3.connect(DATA_FILE)
cur = con.cursor()
data = cur.execute(f'SELECT * FROM {TABLE}')

with open('output.csv', 'w', newline = '') as f:
   writer = csv.writer(f)
   writer.writerow(['firmware', 'web_server_type'])
   writer.writerows(data)
