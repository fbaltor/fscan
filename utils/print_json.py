import json
import sys
import pprint


json_file = sys.argv[1]

with open(json_file, 'r+') as f:
    data = f.read()
    json_data = json.loads(data)
    json_data = pprint.pformat(json_data)

    f.seek(0)
    f.truncate()
    f.write(json_data)
