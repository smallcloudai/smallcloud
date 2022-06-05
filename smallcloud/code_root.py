import os, shutil, subprocess, datetime, json, requests


def detect_code_root():
    """
    Expected directory structure:
    my-code/
    my-code/.smc_code_root     -- indicates that this folder and all its subfolders necessary to run your code.
    my-code/necessary-thing1/
    my-code/necessary-thing2/
    my-code/my-script/this-does-the-work.py     -- imports thing1, thing2, does the work.

    This function returns path to 'my-code', a path to be uploaded to a remote machine or packed into a zip.
    It works by looking at the current working directory and up, looing for a file named '.smc_code_root'.
    """
    start_dir = os.getcwd()
    p = start_dir
    while 1:
        if os.path.exists(p + "/.smc_code_root.sh"):
            break
        if p == os.path.dirname(p):
            print("Cannot find code root, searched the current directory '%s' and up." % start_dir)
            print("Please create a file '.smc_code_root.sh' in the directory you want to upload to your VM, for example:")
            print(f"touch {start_dir}/.smc_code_root.sh")
            print("You can leave this file empty or put initialization commands here, such as \"pip install -r requirements.txt\" or \"echo 'export VAR=value' >> ~/.profile\"")
            quit(0)
        p = os.path.dirname(p)
    p += "/"  # that makes rsync happy
    print("Code root detected at: %s" % p)
    return p


def code_to_zip():
    fn = "codezip_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    assert shutil.which("7zr") is not None, "ubuntu: apt-get install p7zip-full\nmac: brew install p7zip"
    root = detect_code_root()
    path_from_home = root.replace(os.path.expanduser('~/'), '', 1)
    # If you use several code roots, path_from_home helps rsync destination to be unique.
    tmp = os.path.join("/tmp/smc-temp/", path_from_home)
    os.makedirs(tmp, exist_ok=True)
    cmd = ["rsync", "-rplu", "--delete", ".", tmp, "--filter=:- .gitignore", "--exclude=.git"]
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ["7za", "-bso0", "-y", "a", f"/tmp/smc-temp/{fn}.7z", "."]
    # -bs{o|e|p}{0|1|2} : set output stream for output/error/progress line
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"/tmp/smc-temp/{fn}.7z"
