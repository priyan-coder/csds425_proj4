import sys
import os
from os.path import join
import subprocess
import hashlib
# exec using the following command
# python script.py input_file_directory_path output_directory_path
# assuming executable is in the same directory as script.py

BUF_SIZE = 512


def get_hash(f_path):
    sha1 = hashlib.sha1()
    with open(f_path, 'rb') as file:
        block = file.read(BUF_SIZE)
        while block:
            sha1.update(block)
            block = file.read(BUF_SIZE)
    return sha1.hexdigest()


if __name__ == "__main__":
    path_to_input_directory = sys.argv[1]
    path_to_output_directory = sys.argv[2]
    trace_file_paths = []
    executable = "./proj4"
    modes = ["-s", "-l", "-p", "-m"]

    for file in os.listdir(path_to_input_directory):
        if file.endswith(".trace"):
            trace_file_paths.append(join(path_to_input_directory, file))

    print("--------------------------------Testing--------------------------------")
    for trace in trace_file_paths:
        for mode in modes:
            # just the name of the file without the .trace extension
            fname = os.path.splitext(trace)[0]
            # corresponding sample test output file if given
            expected_file = join(path_to_input_directory,
                                 fname + mode + ".out")
            if os.path.exists(expected_file):
                output_filename = fname + "-test" + mode + ".out"
                # test output file to be created in output dir
                filepath = join(path_to_output_directory, output_filename)
                print("Writing output file to ", filepath)
                if not os.path.exists(path_to_output_directory):
                    os.makedirs(path_to_output_directory)
                f = open(filepath, "w")
                print("Running: " + executable +
                      " -t" + " " + trace + " " + mode)
                # saving the output to our test file in output dir
                subprocess.call([executable, "-t", trace, mode], stdout=f)
                f.close()
                if mode == "-m":
                    # sort output before comparing shasum
                    subprocess.call(
                        ["sort", expected_file, "-o", expected_file])
                    subprocess.call(["sort", filepath, "-o", filepath])
                print("{}: {}".format(expected_file, get_hash(expected_file)))
                print("{}: {}".format(filepath, get_hash(filepath)))
                if get_hash(expected_file) == get_hash(filepath):
                    print("Passed " + u'\u2705')
                else:
                    print("Failed " + u'\u274c')
