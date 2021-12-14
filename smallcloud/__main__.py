import os, sys, json, time, subprocess, termcolor, traceback
import urllib, ssl
import urllib.request
import urllib.error
import pandas

 # try click


v1_url = "https://www.smallcloud.ai/v1/"
if os.environ.get("staging"):
    v1_url = v1_url.replace("www", "staging")
if os.environ.get("local"):
    v1_url = v1_url.replace("www", "local")


config_dir = os.path.expanduser("~/.config/smallcloud.ai")
config_file = config_dir + "/cli_config"
config_username = None


global_option_dryrun = False
global_option_verbose = False
global_option_json = False


def fetch_json(url, post_json=None):
    t0 = time.time()
    try:
        if post_json is not None:
            print(json.dumps(post_json))
        req = urllib.request.Request(
            url,
            json.dumps(post_json).encode("utf-8") if post_json else None,
            {'Content-Type': 'application/json'}
        )
        j = json.loads(urllib.request.urlopen(req).read())
        t1 = time.time()
        print_if_appropriate("%0.2fs %s" % (t1 - t0, url))
    except urllib.error.URLError:
        print("ERROR %s" % (url))
        traceback.print_exc()
        quit(1)
    return j


def run(cmd, dry=False, verbose=None, stdout=None, stderr=None, **kwargs):
    verbose = int(os.environ.get("verbose", "0"))
    if not verbose:
        stdout = subprocess.DEVNULL if stdout is None else stdout
        stderr = subprocess.DEVNULL if stderr is None else stderr
    if not global_option_json:
        print(" ".join(cmd))
    if global_option_dryrun:
        return 0
    completed_process = subprocess.run(cmd, stdout=stdout, stderr=stderr, **kwargs)
    return completed_process.returncode


def print_if_appropriate(*args):
    if not global_option_json:
        print(*args)


def print_table(resp):
    if global_option_json:
        print(json.dumps(resp, indent=4))
        return
    if len(resp) == 0:
        print("empty result")
        return
    flatlist = None
    if isinstance(resp, dict):
        keys = sorted(resp.keys())
        if isinstance(resp[keys[0]], dict):
            flatlist = [{'name': k, **resp[k]} for k in keys]
    elif isinstance(resp, list):
        flatlist = resp
    elif isinstance(resp, str):
        print("server returned:\n%s" % str(resp))
        quit(1)
    if flatlist is not None:
        df = pandas.DataFrame()
        for column in flatlist[0].keys():
            df[column] = [x[column] for x in flatlist]
        print(df)


def code_root():
    p = os.path.dirname(__file__)
    while 1:
        if os.path.exists(p + "/smallcloud/smallcloud/__main__.py"):
            break
        if p == os.path.dirname(p):
            assert 0, "cannot find code root, started from %s" % __file__
        p = os.path.dirname(p)
    p += "/"  # that makes rsync happy
    print_if_appropriate("code root detected at: %s" % p)
    return p


def read_config_file():
    if not os.path.exists(config_file):
        return
    with open(config_file, "r") as f:
        config = json.loads(f.read())
    global config_username
    if time.time() > config["expiry"]:
        print("your login credentials are expired, please re-login")
    else:
        config_username = config["login"]


def command_login(*args):
    assert len(args) <= 1
    if len(args) == 0:
        username = input("username: ")
    else:
        username = args[0]
    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, "w") as f:
        f.write(json.dumps({
            "login": username,
            "expiry": time.time() + 365*86400,
            }, indent=4))
    print("login credentials were stored in %s, expires in one year" % config_file)
    print("try this:")
    print(termcolor.colored("s list", attrs=["bold"]))
    print(termcolor.colored("s free", attrs=["bold"]))
    print(termcolor.colored("s reserve my_new_job a5000 4", attrs=["bold"]))


def command_logout():
    if not config_username:
        print("you are not logged in")
        return
    os.remove(config_file)
    print("logged out")


def make_sure_have_login():
    if not config_username:
        print("please login to complete this operation")
        quit(1)


def command_free(*args):
    # TODO cluster name
    free_json = fetch_json(v1_url + "free")
    print_table(free_json)


def command_reserve(task_name, gpu_type, gpu_min, gpu_max=None, gpu_incr=None):
    make_sure_have_login()
    print("task:", task_name)
    print("account:", config_username)
    print("gpu_type=%s * gpu_min=%s gpu_max=%s gpu_incr=%s" % (gpu_type, gpu_min, gpu_max, gpu_incr))
    post_json = {
        "account": config_username,
        "task_name": task_name,
        "gpu_type": gpu_type,
        "gpu_min": gpu_min,
        }
    if gpu_max is not None:
        post_json["gpu_max"] = gpu_max
    if gpu_incr is not None:
        post_json["gpu_incr"] = gpu_incr
    ret_json = fetch_json(v1_url + "reserve", post_json)
    print(ret_json)


def command_list():
    make_sure_have_login()
    resp = fetch_json(v1_url + "list")
    print_table(resp)


def command_upload_code(*args, **kwargs):
    user = kwargs.get("user", "user")
    coderoot = code_root()
    upload_dest = []
    if len(args) == 0:
        print("please specify computers to upload your code, for example \"myjob05*\", also try \"list\"")
        return
    for j in args:
        nodes_json = fetch_json(v1_url + "nodes")
        for node_rec in nodes_json:
            node_name = node_rec["node_name"]
            import fnmatch
            if fnmatch.fnmatch(node_name, j):
                upload_dest.append({'computer': node_name, 'ip': node_rec["ip_internal"], 'port': node_rec["port"], 'user': user})
    print_if_appropriate("uploading code to:")
    print_table(upload_dest)
    for dest in upload_dest:
        # "-u" update based on modification time
        # "-c" update based on checksum, not date, because git might clone newer files than your modified ones
        # "--delete" -- nice to have, but has unexpected effects
        cmd = [
            "rsync", "-rpl", "-c", "--itemize-changes", coderoot, f"{dest['user']}@{dest['ip']}:code/", "--filter=:- .gitignore", "--exclude=.git",
            "-e", f"ssh -p {dest['port']} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
            ]
        r = run(cmd, stdout=sys.stdout, stderr=sys.stderr)
        assert r==0, r

def command_ssh(*args, **kwargs):
    assert len(args) == 1, "can only ssh to one server at a time"
    user = kwargs.get("user", "user")
    job = args[0]
    nodes_json = fetch_json(v1_url + "nodes")
    computer = None
    for node_rec in nodes_json:
        node_name = node_rec["node_name"]
        if node_name==job:
            computer = {'ip': node_rec["ip_internal"], 'port': node_rec["port"], 'user': user}
    if not computer:
        print("computer %s not found" % job)
        return
    cmd = [
        "/usr/bin/ssh",
        "%s@%s" % (user, computer['ip']),
        "-p", "%i" % computer['port'],
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        ]
    print("ssh", " ".join(cmd))
    # this replaces the current process with ssh
    os.execv("/usr/bin/ssh", cmd)


def command_nodes(*args):
    nodes_json = fetch_json(v1_url + "nodes")
    print_table(nodes_json)


def command_scheduled(*args):
    free_json = fetch_json(v1_url + "scheduled")
    print_table(free_json)


def cli_command(command, *args, **kwargs):
    if command == "free":
        command_free()

    elif command == "login":
        command_login(*args)

    elif command == "logout":
        command_logout()

    elif command == "reserve":
        command_reserve(*args, **kwargs)

    elif command in ["list", "jobs"]:
        command_list()

    elif command == "ssh":
        command_ssh(*args, **kwargs)

    elif command == "upload-code":
        command_upload_code(*args, **kwargs)

    elif command == "nodes":
        command_nodes()

    elif command == "scheduled":
        command_scheduled()

    # elif command == "tail":
    #     print("tail!")

    else:
        assert 0, "unknown command '%s'" % command


if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="normally output tables are printed using pandas, switch json output")
    parser.add_argument("--dry", action="store_true", help="do not run commands, just print them")
    parser.add_argument("--verbose", action="store_true", help="show stdout of any subcommands")
    parser.add_argument("--user", help="specify user name for 'ssh' and 'upload-code', default user name is 'user'")
    parser.add_argument("command", nargs="+", help="one of: free, list, ssh, upload-code, tail")
    args = parser.parse_args()
    global_option_dryrun = args.dry
    global_option_json = args.json
    global_option_verbose = args.verbose
    read_config_file()
    kwargs = {}
    if args.user:
        kwargs["user"] = args.user
    cli_command(*args.command, **kwargs)
