import subprocess
import sys
import tempfile
import shutil
import os


def pack_python_extension(setup_path, target_path, additional_path):
    with tempfile.TemporaryDirectory() as tmp:
        args = [sys.executable, '-m', 'pip', 'wheel', '-w', tmp]
        if additional_path is not None:
            args.extend(['-f', additional_path])

        args.append(setup_path)
        result = subprocess.run(args, capture_output=True)

        if result.returncode != 0:
            print("Error building python extension: {}".format(result.stderr.decode('utf-8')), file=sys.stderr)
            return result.returncode

        lib_folder = os.path.join(target_path, 'lib')
        if not os.path.exists(lib_folder):
            os.makedirs(lib_folder)
        if not os.path.isdir(lib_folder):
            print('ERROR - {} is file, needs to be a folder'.format(lib_folder), file=sys.stderr)
            return 1
        for file in os.listdir(tmp):
            src_file = os.path.join(tmp, file)
            dst_file = os.path.join(lib_folder, file)
            shutil.copy(src=src_file, dst=dst_file)
    print("Python extension packed successfully to {}".format(lib_folder))
    return 0
