import argparse
import tarfile

class RuleEvaluator():

    @staticmethod
    def apply_simple_rule(tar_path):
        with tarfile.open(tar_path) as tf:
            for file in tf.getmembers():
                if file.name.endswith('.php'):
                    return 'php'
                if file.name.endswith('.jcgi'):
                    return 'Java CGI'
                if file.name.endswith('.lua'):
                    return 'LuCI'
                if file.name.endswith('.asp'):
                    return 'ASP'
                if (file.isfile()):
                    content = tf.extractfile(file).read()
                    if b'#!/usr/bin/perl' in content:
                        return 'Perl CGI'
                    if b'#!/usr/bin/python' in content:
                        return 'Python CGI'
                    if b'<%@ ' in content or b'<!--#include' in content or b'Server.CreateObject' in content:
                        return 'ASP'
            return 'Unknown'
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action = 'store')
    args = parser.parse_args()

    print(RuleEvaluator.apply_simple_rule(args.input))

    
if __name__ == '__main__':
    main()