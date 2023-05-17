import argparse
import tarfile

class RuleEvaluator():
    def __init__(self, input_tar_filesystem):
        self.input_tar_filesystem = input_tar_filesystem
        self.tar = tarfile.open(self.input_tar_filesystem)


    def apply_simple_rule(self):
        for file in self.tar.getnames():
            if file.endswith('.php'):
                return 'php'
            if file.endswith('.jcgi'):
                return 'Java CGI'
            if file.endswith('luci'):
                return 'LuCI'
            else:
                return 'Unknown'
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action = 'store')
    args = parser.parse_args()

    r = RuleEvaluator(args.input)
    for file in r.tar.getnames():
        if file.endswith('.php'):
            print('PHP')
            return

    
if __name__ == '__main__':
    main()