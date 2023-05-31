import argparse
import tarfile
import os

import magic


class RuleEvaluator():

    @staticmethod
    def _apply_rule_for_tar(tar_path):
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
        
    @staticmethod
    def _apply_rule_for_directory(dir_path):
        for root, dirs, files in os.walk(dir_path, topdown = False):
            for file_name in files:
                if file_name.endswith('.php'):
                    return 'php'
                if file_name.endswith('.jcgi'):
                    return 'Java CGI'
                if file_name.endswith('.lua'):
                    return 'LuCI'
                if file_name.endswith('.asp'):
                    return 'ASP'
                
                file_path = os.path.join(root, file_name)
                if magic.from_file(file_path) == 'ASCII text':
                    with open(file_path) as f:
                        content = f.read()
                        if '#!/usr/bin/perl' in content:
                            return 'Perl CGI'
                        if '#!/usr/bin/python' in content:
                            return 'Python CGI'
                        if '<%@ ' in content or '<!--#include' in content or 'Server.CreateObject' in content:
                            return 'ASP'
                        
        return 'Unknown'

    @staticmethod
    def apply_simple_rule(target_path):
        if os.path.isdir(target_path):
            return RuleEvaluator._apply_rule_for_directory(target_path)

        if target_path.endswith('.tar.gz'):
            return RuleEvaluator._apply_rule_for_tar(target_path)

        raise TypeError(f'Could not apply rule to {target_path}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', action = 'store')
    args = parser.parse_args()

    print(RuleEvaluator.apply_simple_rule(args.input))
    
if __name__ == '__main__':
    main()