import os, shutil, subprocess, datetime, json
from smallcloud import config
import urllib
import urllib.request
import urllib.error


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
        if os.path.exists(p + "/.smc_code_root"):
            break
        if p == os.path.dirname(p):
            print("Cannot find code root, searched the current directory '%s' and up." % start_dir)
            print("Please create a file '.smc_code_root' in the directory you want to upload to your VM, for example:")
            print(f"touch {start_dir}/.smc_code_root")
            quit(0)
        p = os.path.dirname(p)
    p += "/"  # that makes rsync happy
    print("Code root detected at: %s" % p)
    return p


def code_to_zip():
    fn = "smc_code_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    assert shutil.which("7za") is not None, "ubuntu: apt-get install p7zip-full\nmac: brew install p7zip"
    root = detect_code_root()
    short = root.replace(os.path.expanduser('~'), '', 1)
    tmp = "/tmp" + short
    os.makedirs(tmp, exist_ok=True)
    cmd = ["rsync", "-rplu", "--delete", ".", tmp, "--filter=:- .gitignore", "--exclude=.git"]
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=root)
    cmd = ["7za", "-bso0", "-y", "a", f"/tmp/{fn}.zip", "."]
    # -bs{o|e|p}{0|1|2} : set output stream for output/error/progress line
    print(" ".join(cmd))
    subprocess.check_call(cmd, cwd=tmp)
    return f"/tmp/{fn}.zip"


def code_upload(zip_fn):
    MAX_ZIP_SIZE = 5*1024*1024
    zip_data = open(zip_fn, "rb").read()
    if len(zip_data) > MAX_ZIP_SIZE:
        raise Exception("Maximum code archive size is %0.1fM, your code %0.1fM" % (MAX_ZIP_SIZE/1024/1024, len(zip_data)/1024/1024))
    url = config.v1_url + "zip-upload"
    print(url)
    req = urllib.request.Request(url, zip_data, config.account_and_secret_key_headers())
    try:
        result = urllib.request.urlopen(req).read()
        j = json.loads(result)
    except urllib.error.HTTPError as e:
        print(e.read().decode())
        quit(1)
    print("AAAA")
    print(j)
