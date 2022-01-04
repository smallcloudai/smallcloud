import os, sys, json, time, subprocess, termcolor
import urllib, ssl
import urllib.request
import urllib.error

 # try click


v1_url = "https://www.smallcloud.ai/v1/"
if os.environ.get("staging"):
    v1_url = v1_url.replace("www", "staging")
if os.environ.get("local"):
    v1_url = v1_url.replace("www", "local")


config_dir = os.path.expanduser("~/.config/smallcloud.ai")
config_file = config_dir + "/cli_config"
ssh_rsa_id = config_dir + "/dedicated_ssh_rsa_id"
config_username = None


global_option_dryrun = False
global_option_verbose = False
global_option_json = False


def fetch_json(url, post_json=None, get_params=None):
    t0 = time.time()
    try:
        if get_params is not None:
            url += "?" + urllib.parse.urlencode(get_params)
        elif post_json is not None:
            print(json.dumps(post_json))
        req = urllib.request.Request(
            url,
            json.dumps(post_json).encode("utf-8") if post_json else None,
            {'Content-Type': 'application/json'}
        )
        result = urllib.request.urlopen(req).read()
        t1 = time.time()
        print_if_appropriate("%0.2fs %s" % (t1 - t0, url))
    except urllib.error.URLError:
        print("ERROR %s" % (url))
        import traceback
        traceback.print_exc()
        quit(1)
    try:
        j = json.loads(result)
    except ValueError:
        print("response from server is not a json")
        print(result.decode("utf-8"))
        quit(1)
    return j


def run(cmd, dry=False, verbose=None, stdout=None, stderr=None, **kwargs):
    verbose = int(os.environ.get("verbose", "0"))
    if not verbose:
        stdout = subprocess.DEVNULL if stdout is None else stdout
    stderr = stderr or subprocess.PIPE
    if not global_option_json:
        print(" ".join(cmd))
    if global_option_dryrun:
        return 0
    completed_process = subprocess.run(cmd, stdout=stdout, stderr=stderr, **kwargs)
    if completed_process.returncode != 0:
        print("RETCODE: %s" % completed_process.returncode)
    if completed_process.stderr and (verbose or completed_process.returncode != 0):
        print("STDERR: %s" % completed_process.stderr.decode("utf-8"))
    return completed_process.returncode


def print_if_appropriate(*args):
    if not global_option_json:
        print(*args)


def print_table(resp, omit_for_brevity=[]):
    if global_option_json:
        print(json.dumps(resp, indent=4))
        return
    if len(resp) == 0:
        print("empty result")
        return
    flatlist = None
    if isinstance(resp, dict):
        keys = sorted(resp.keys())
        assert isinstance(resp[keys[0]], dict)
        flatlist = [resp[k] for k in keys]
    elif isinstance(resp, list):
        flatlist = resp
    elif isinstance(resp, str):
        print("server returned:\n%s" % str(resp))
        quit(1)
    def print_datetime(ts):
        if ts==0: return "-"
        full = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time()))):
            return time.strftime("%H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))):
            return time.strftime("%a %H:%M:%S", time.localtime(ts))
        return full
    if flatlist is not None:
        import pandas   # is slow, don't import at the top of the file.
        df = pandas.DataFrame()
        for column in flatlist[0].keys():
            if column in omit_for_brevity:
                continue
            if not column.startswith("ts_"):
                df[column.upper()] = [x[column] for x in flatlist]
            else:
                df[column.upper()] = [print_datetime(x[column]) for x in flatlist]
        print(df)


def pretty_print_response(json):
    if isinstance(json, dict) and "retcode" in json:
        retcode = json["retcode"]
        color = "green" if retcode == "OK" else "red"
        print(termcolor.colored(retcode, color), json["human_readable_message"])
        return
    print(json)


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
        print("Your login credentials are expired, please re-login.")
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
    print("Login credentials were stored in %s, will expire in one year." % config_file)
    print("Try this:")
    print(termcolor.colored("s list", attrs=["bold"]))
    print(termcolor.colored("s free", attrs=["bold"]))
    print(termcolor.colored("s reserve my-new-job a5000 4", attrs=["bold"]))


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
    free_json = fetch_json(v1_url + "free", get_params={"account": config_username})
    print_table(free_json)


def command_reserve(task_name, gpu_type, gpu_min, gpu_max=None, gpu_incr=None):
    make_sure_have_login()
    print("reserving %s * %s" % (gpu_type, gpu_min))
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
    pretty_print_response(ret_json)


def command_jobs():
    make_sure_have_login()
    resp = fetch_json(v1_url + "jobs", get_params={"account": config_username})
    day_ago = time.time() - 24*3600
    if resp == []:
        print("There are no jobs yet. You can start one using:\n" + termcolor.colored("s reserve my-new-job a5000 4", attrs=["bold"]))
        return
    finished_less_than_day_ago = [x for x in resp if x["ts_finished"] == 0 or x["ts_finished"] > day_ago]
    print_table(finished_less_than_day_ago, ["cluster_name", "tenant_name", "tenant_image", "ts_placed", "gpu_type", "gpus_min", "gpus_max", "gpus_incr", "nice"])


def command_delete(*task_names):
    make_sure_have_login()
    for tname in task_names:
        resp = fetch_json(v1_url + "delete", get_params={"account": config_username, "task_name": tname})
        pretty_print_response(resp)


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
    computer_name = args[0]
    sshables = fetch_json(v1_url + "list-ssh-able", get_params={"account": config_username})
    closest_match = None
    closest_match_dist = 1e10
    import difflib
    for rec in sshables:
        if rec["name"] == computer_name:
            break
        dist = difflib.SequenceMatcher(None, rec["name"], computer_name).ratio()
        if dist > 0.8 and dist < closest_match_dist:
            closest_match = rec
            closest_match_dist = dist
    else:
        print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        if closest_match is not None:
            print("Did you mean \"%s\"?" % closest_match["name"])
        return
    cmd = [
        "ssh",
        "%s@%s" % (user, rec['ssh_addr']),
        "-p", "%i" % rec['ssh_port'],
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        ]
    print(" ".join(cmd))
    # this replaces the current process with ssh
    os.execv("/usr/bin/ssh", cmd)


def command_nodes():
    nodes_json = fetch_json(v1_url + "nodes")
    print_table(nodes_json)


def command_scheduled():
    free_json = fetch_json(v1_url + "scheduled")
    print_table(free_json)


def command_ssh_keygen(*args):
    try:
        os.unlink(ssh_rsa_id)
    except FileNotFoundError:
        pass
    r = run(["ssh-keygen", "-f", ssh_rsa_id, "-N", ""])
    assert r==0, r
    resp = fetch_json(v1_url + "ssh-public-key-upload", post_json={"account": config_username, "ssh_public_key": open(ssh_rsa_id + ".pub").read()})
    pretty_print_response(resp)


def command_ssh_upload(*args):
    assert len(args) == 1, "please specify a file to upload, such as ~/.ssh/id_rsa.pub\n(do this if you want simple ssh without many additional options to work, otherwise use \"s ssh-keygen\" to create a dedicated key)"
    resp = fetch_json(v1_url + "ssh-public-key-upload", post_json={
        "account": config_username,
        "ssh_public_key": open(os.path.expanduser(args[0])).read()
    })
    pretty_print_response(resp)


def command_promo(*args):
    if len(args) == 0:
        print("This command applies a promo code (might add money to your account).")
        return
    assert len(args) == 1
    resp = fetch_json(v1_url + "apply-promo", get_params={"account": config_username, "code": args[0]})
    pretty_print_response(resp)


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
        command_jobs()

    elif command in ["delete", "remove"]:
        command_delete(*args)

    elif command == "ssh":
        command_ssh(*args, **kwargs)

    elif command == "upload-code":
        command_upload_code(*args, **kwargs)

    elif command == "nodes":
        command_nodes()

    elif command == "scheduled":
        command_scheduled()

    elif command == "ssh-keygen":
        command_ssh_keygen()

    elif command == "ssh-upload":
        command_ssh_upload(*args)

    elif command == "promo":
        command_promo(*args)

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
