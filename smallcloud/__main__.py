import os, sys, json, time, subprocess, termcolor
import urllib
import urllib.request
import urllib.error

 # Read this source code, nice and clean!


v1_url = "https://www.smallcloud.ai/v1/"
if os.environ.get("staging"):
    v1_url = v1_url.replace("www", "staging")
if os.environ.get("local"):
    v1_url = v1_url.replace("www", "local")


config_dir = os.path.expanduser("~/.config/smallcloud.ai")
config_file = config_dir + "/cli_config"
ssh_rsa_id = config_dir + "/dedicated_ssh_rsa_id"
known_hosts_file = config_dir + "/known_hosts"
config_username = None
config_secret_api_key = None
global_option_json = False


def printhl(s):
    print(termcolor.colored(s, attrs=["bold"]))


def fetch_json(url, post_json=None, get_params=None, headers={}):
    t0 = time.time()
    try:
        if get_params is not None:
            url += "?" + urllib.parse.urlencode(get_params)
        elif post_json is not None:
            print(json.dumps(post_json))
        req = urllib.request.Request(
            url,
            json.dumps(post_json).encode("utf-8") if post_json else None,
            {'Content-Type': 'application/json', **headers}
        )
        result = urllib.request.urlopen(req).read()
        t1 = time.time()
        print_if_appropriate("%0.2fs %s" % (t1 - t0, url))
    except urllib.error.URLError:
        print("ERROR %s" % (url))
        raise
    try:
        j = json.loads(result)
    except ValueError:
        print("Response from server is not a json:")
        print(result.decode("utf-8"))
        quit(1)
    if "retcode" in j and j["retcode"] != "OK":
        print(termcolor.colored(j["retcode"], "red"), j["human_readable_message"])
        quit(1)
    return j


def run(cmd, stdout=None, stderr=None, **kwargs):
    # This function runs 'rsync' and 'ssh-keygen'
    # To debug, use:
    #  verbose=1 dry=1 s command
    verbose = int(os.environ.get("verbose", "0"))
    if not verbose:
        stdout = subprocess.DEVNULL if stdout is None else stdout
    stderr = stderr or subprocess.PIPE
    if not global_option_json:
        print(" ".join(cmd))
    dry = int(os.environ.get("dry", "0"))
    if dry:
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
        print("Empty result")
        return
    if isinstance(resp, dict):
        keys = sorted(resp.keys())
        assert isinstance(resp[keys[0]], dict)
        flatlist = [resp[k] for k in keys]
    elif isinstance(resp, list):
        flatlist = resp
    else:
        print("Server returned:\n%s" % str(resp))
        quit(1)
    def print_datetime(ts):
        if ts==0: return "-"
        full = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time()))):
            return time.strftime("%H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))):
            return time.strftime("%a %H:%M:%S", time.localtime(ts))
        return full
    import pandas   # is slow, don't import at the top of the file.
    df = pandas.DataFrame()
    for column in flatlist[0].keys():
        if column in omit_for_brevity:
            continue
        if not column.startswith("ts_") and not column.endswith("_ts"):
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
    start_dir = os.getcwd()
    p = start_dir
    while 1:
        if os.path.exists(p + "/.smc_code_root"):
            break
        if p == os.path.dirname(p):
            print("Cannot find code root, searched the current directory '%s' and up." % start_dir)
            print("Please create a file '.smc_code_root' in the directory you want to upload to your VM, for example:")
            printhl(f"touch {start_dir}/.smc_code_root")
            quit(0)
        p = os.path.dirname(p)
    p += "/"  # that makes rsync happy
    print_if_appropriate("Code root detected at: %s" % p)
    return p


def read_config_file():
    if not os.path.exists(config_file):
        return
    try:
        with open(config_file, "r") as f:
            config = json.loads(f.read())
    except ValueError:
        print("Empty or invalid config file: %s (delete it to relogin)" % config_file)
        quit(1)
    global config_username, config_secret_api_key
    if "expires_ts" in config and time.time() > config["expires_ts"] > 0:
        print("Your login credentials are expired, please re-login.")
    else:
        config_username = config["account_name"]
        config_secret_api_key = config["secret_api_key"]


def command_login():
    print("Please open this link in your browser:\n")
    print(termcolor.colored(v1_url.replace("/v1/", "/cli-login"), attrs=["bold"]))
    ticket = input("\nand copy-paste a response here: ")
    resp = fetch_json(v1_url + "cli-login-response", get_params={"ticket": ticket})
    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, "w") as f:
        f.write(json.dumps({
            "account_name": resp["account_name"],
            "expires_ts": (resp["expires_ts"] if "expires_ts" in resp else 365*24*60*60 + time.time()),
            "secret_api_key": resp["secret_api_key"],
            }, indent=4))
    os.chmod(config_file, 0o600)
    print("Login successful: %s" % resp["account_name"])
    print("Account name and the Secret API Key were stored in %s" % config_file)
    print("Try this:")
    print(termcolor.colored("s list", attrs=["bold"]))
    print(termcolor.colored("s free", attrs=["bold"]))
    print(termcolor.colored("s reserve a5000 4 myexperiment00", attrs=["bold"]))


def command_logout():
    if not config_username:
        print("You are not logged in")
        return
    os.remove(config_file)
    print("Logged out")


def make_sure_have_login():
    if not config_username:
        print("Please login to complete this operation")
        quit(1)


def account_and_secret_key():
    if not config_username:
        return {}   # some commands work without login
    return {
        "X-Account": config_username,
        "X-Secret-API-Key": config_secret_api_key,
    }


def command_free():
    free_json = fetch_json(v1_url + "free", headers=account_and_secret_key())
    print_table(free_json)


def command_reserve(args):
    make_sure_have_login()
    gpu_min = args.count
    post_json = {
        "task_name": args.job_name,
        "gpu_type": args.gpu_type,
        "gpu_min": int(gpu_min),
        }
    if args.os:
        post_json["tenant_image"] = args.os
    ret_json = fetch_json(v1_url + "reserve", post_json, headers=account_and_secret_key())
    pretty_print_response(ret_json)


def command_jobs():
    make_sure_have_login()
    resp = fetch_json(v1_url + "jobs", headers=account_and_secret_key())
    day_ago = time.time() - 24*3600
    if resp == []:
        print("There are no jobs yet. You can start one using:\n" + termcolor.colored("s reserve a5000 4 myexperiment00", attrs=["bold"]))
        return
    finished_less_than_day_ago = [x for x in resp if x["ts_finished"] == 0 or x["ts_finished"] > day_ago]
    hidden = len(resp) - len(finished_less_than_day_ago)
    if hidden:
        print(termcolor.colored("finished more than a day ago: %i" % hidden, "white"))
    print_table(finished_less_than_day_ago, ["cluster_name", "tenant_name", "tenant_image", "ts_placed", "gpu_type", "gpus_min", "gpus_max", "gpus_incr", "nice", "ed25519"])


def command_delete(args):
    make_sure_have_login()
    for tname in args.job_name:
        resp = fetch_json(v1_url + "delete", get_params={"task_name": tname}, headers=account_and_secret_key())
        pretty_print_response(resp)


def fetch_sshables():
    sshables = fetch_json(v1_url + "list-ssh-able", headers=account_and_secret_key())
    known_hosts = []
    for rec in sshables:
        if rec["ed25519"]:
            known_hosts.append("[%s]:%i %s" % (rec['ssh_addr'], rec['ssh_port'], rec['ed25519']))
    return sshables, known_hosts


def save_known_hosts(known_hosts):
    with open(known_hosts_file, "wt") as f:
        f.write("\n".join(known_hosts) + "\n")
    os.chmod(known_hosts_file, 0o600)


def command_ssh(args):
    if "@" not in args.job_name:
        computer_name = args.job_name
        user = "user"
    else:
        user, computer_name = args.job_name.split("@")
    closest_match = None
    closest_match_dist = 1e10
    sshables, known_hosts = fetch_sshables()
    import difflib
    right_rec = None
    for rec in sshables:
        if rec["name"] == computer_name:
            right_rec = rec
        dist = difflib.SequenceMatcher(None, rec["name"], computer_name).ratio()
        if dist > 0.8 and dist < closest_match_dist:
            closest_match = rec
            closest_match_dist = dist
    if right_rec is None:
        print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        if closest_match is not None:
            print("Did you mean \"%s\"?" % closest_match["name"])
        return
    cmd = [
        "ssh",
        "%s@%s" % (user, right_rec['ssh_addr']),
        "-p", "%i" % right_rec['ssh_port'],
    ]
    if right_rec["ed25519"]:  # Ether way strict checking is on!
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    cmd.extend(*args.args)
    print(" ".join(cmd))
    # this replaces the current process with ssh
    os.execv("/usr/bin/ssh", cmd)


def command_scp(args):
    job_name, path = args.dst.split(":")
    if "@" in job_name:
        user, computer_name = job_name.split("@")
    else:
        user = "user"
        computer_name = job_name
    right_rec = None
    sshables, known_hosts = fetch_sshables()
    for rec in sshables:
        if rec["name"] == computer_name:
            right_rec = rec
    if right_rec is None:
        print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        quit(1)
    cmd = ["scp", "-P", "%i" % right_rec['ssh_port'], args.src]
    if right_rec["ed25519"]:
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    cmd.append("%s@%s:%s" % (user, right_rec['ssh_addr'], path))
    if args.args:
        cmd.append(*args.args)
    print(" ".join(cmd))
    # this replaces the current process with scp
    os.execv("/usr/bin/scp", cmd)


def command_upload_code(args):
    coderoot = code_root()
    sshables, known_hosts = fetch_sshables()
    save_known_hosts(known_hosts)
    upload_dest = []
    upload_user = []
    for j in args.job_name:  # TODO(d.ageev): may be it is node name?
        if "@" in j:
            user, computer_name = j.split("@")
        else:
            user = "user"
            computer_name = j
        for rec in sshables:
            import fnmatch
            if fnmatch.fnmatch(rec["name"], computer_name):
                upload_dest.append(rec)
                upload_user.append(user)
    print_if_appropriate("Uploading code to:")
    print_table(upload_dest, omit_for_brevity="ed25519")
    for rec, user in zip(upload_dest, upload_user):
        # "-u" update based on modification time
        # "-c" update based on checksum, not date, because git might clone newer files than your modified ones
        # "--delete" -- nice to have, but has unexpected effects
        ssh_cmd = [
            "ssh",
            "-p", "%i" % rec["ssh_port"],
        ]
        if rec["ed25519"]:
            add_ssh_identity_if_exists(ssh_cmd)
            ssh_cmd.extend(["-o", "UserKnownHostsFile=%s" % known_hosts_file])
        cmd = [
            "rsync", "-rpl", "-c", "--itemize-changes", coderoot, f"{user}@{rec['ssh_addr']}:code/", "--filter=:- .gitignore", "--exclude=.git",
            "-e", " ".join(ssh_cmd),
            ]
        r = run(cmd, stdout=sys.stdout, stderr=sys.stderr)
        assert r==0, r


def command_nodes():
    nodes_json = fetch_json(v1_url + "nodes", headers=account_and_secret_key())
    print_table(nodes_json)


def command_ssh_keygen(args):
    jobs_for_warning = fetch_json(v1_url + "jobs", headers=account_and_secret_key())
    jobs_running = [x for x in jobs_for_warning if x["ts_finished"] == 0]
    if len(jobs_running) > 0:
        print(f"You have {len(jobs_running)} jobs running. All ssh-based commands from this computer will start to use a new \"-i {ssh_rsa_id}\" identity file, this might prevent you from logging in to these running machines.")
        quit(1)
    try:
        os.unlink(ssh_rsa_id)
    except FileNotFoundError:
        pass
    r = run(["ssh-keygen", "-f", ssh_rsa_id, "-N", "", *args.args])
    assert r==0, r
    resp = fetch_json(
        v1_url + "ssh-public-key-upload",
        post_json={"ssh_public_key": open(ssh_rsa_id + ".pub").read()},
        headers=account_and_secret_key())
    pretty_print_response(resp)


def command_ssh_upload(args):
    resp = fetch_json(
        v1_url + "ssh-public-key-upload",
        post_json={"ssh_public_key": open(os.path.expanduser(args.filename)).read()},
        headers=account_and_secret_key())
    pretty_print_response(resp)


def add_ssh_identity_if_exists(ssh_cmdline):
    if os.path.exists(ssh_rsa_id):
        ssh_cmdline.extend(["-i", ssh_rsa_id])


def command_promo(args):
    resp = fetch_json(v1_url + "apply-promo", get_params={"code": args.code}, headers=account_and_secret_key())
    pretty_print_response(resp)


def command_billing(subcmd):
    resp = fetch_json(v1_url + subcmd, headers=account_and_secret_key())
    if subcmd == "money":
        print(json.dumps(resp, indent=2))
    else:
        print_table(resp)


def command_prices():
    resp = fetch_json(v1_url + "prices")
    print(resp)


# def cli_command(command, *args):
def cli_command(command, args):
    if command == "free":
        command_free()

    elif command == "login":
        command_login()

    elif command == "logout":
        command_logout()

    elif command == "reserve":
        command_reserve(args)

    elif command in ["list", "jobs"]:
        command_jobs()

    elif command in ["delete", "remove"]:
        command_delete(args)

    elif command == "upload-code":
        command_upload_code(args)

    elif command == "nodes":
        command_nodes()

    elif command == "ssh":
        command_ssh(args)

    elif command == "scp":
        command_scp(args)

    elif command == "ssh-keygen":
        command_ssh_keygen(args)

    elif command == "ssh-upload":
        command_ssh_upload(args)

    elif command == "promo":
        command_promo(args)

    elif command == "billing":
        command_billing("billing-short")

    elif command == "billing-detailed":
        command_billing("billing-detailed")

    elif command in ["$", "money", "dollars"]:
        command_billing("money")

    elif command == "prices":
        command_prices()

    # elif command == "tail":
    #     print("tail!")


def parse_args():
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="This is a command line tool to use Small Magellanic Cloud AI Ltd services. "
                    "Homepage for this tool: https://github.com/smallcloudai/smallcloud")
    parser.add_argument("--json", action="store_true", default=False)

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    subparsers.add_parser(
        "free", help="Print number of free GPUs, works without login.")
    subparsers.add_parser(
        "login", help="Interactive login using your web browser.")
    subparsers.add_parser(
        "logout", help="TODO")
    reserve_subparser = subparsers.add_parser(
        "reserve", help="Reserve GPUs, start the job. Valid gpu_count values are 1, 2, 4, 8, 16, 32, 64. "
                        "Starting from 16, multiple VMs will be launched. "
                        "If the job cannot start immediately, it will be queued.")
    reserve_subparser.add_argument("gpu_type", help="GPU to reserve")
    reserve_subparser.add_argument("count", type=int, help="Number of GPUs")
    reserve_subparser.add_argument("job_name", help="Name of the experiment")
    reserve_subparser.add_argument("--os", help="Operating system")
    subparsers.add_parser(
        "jobs", aliases=["list"], help="Prints your jobs, working and finished.")
    delete_subparser = subparsers.add_parser(
        "delete", aliases=["remove"], help="Delete jobs. Use \"experiment05*\" syntax to delete several jobs.")
    delete_subparser.add_argument("job_name", nargs="+", help="Name of job")
    upload_subparser = subparsers.add_parser(
        "upload-code", help="Upload your source code using rsync. "
                            "Use \"experiment05*\" syntax to upload to several jobs. "
                            "Remote destination is hardcoded as \"/home/user/code/\".")
    upload_subparser.add_argument("job_name", help="Name of job")
    subparsers.add_parser(
        "nodes", help="TODO")
    ssh_subparser = subparsers.add_parser(
        "ssh", help="SSH into the job. By default the user is \"user\". "
                    "You can use \"otheruser@jobname\" syntax if you created more users.")
    ssh_subparser.add_argument("job_name", help="Name of job")
    ssh_subparser.add_argument(
        "--args", nargs="+", type=str, required=False, default=[], help="SSH arguments")
    scp_subparser = subparsers.add_parser(
        "scp", help="Copy a file.")
    scp_subparser.add_argument("src", help="Local file")
    scp_subparser.add_argument("dst", help="Name of job and destination <job_name>:<dst>")
    scp_subparser.add_argument(
        "--args", nargs="+", type=str, required=False, default=[], help="SCP arguments")
    ssh_keygen_subparser = subparsers.add_parser(
        "ssh-keygen", help="Generate a new SSH keypair and upload the public part.")
    ssh_keygen_subparser.add_argument(
        "--args", nargs="+", type=str, required=False, default=[], help="SSH keygen arguments")
    ssh_upload_subparser = subparsers.add_parser(
        "ssh-upload", help="If you prefer, you can upload this computer's public key.")
    ssh_upload_subparser.add_argument(
        "filename", type=str, help="A file to upload, such as ~/.ssh/id_rsa.pub "
                                   "(do this if you want ssh without -i option to work, "
                                   "for a dedicated key use \"s ssh-keygen\")")
    promo_subparser = subparsers.add_parser(
        "promo", help="TODO")
    promo_subparser.add_argument("code", type=str, help="Promo code/")
    subparsers.add_parser(
        "billing", help="TODO")
    subparsers.add_parser(
        "billing-detailed", help="TODO")
    subparsers.add_parser(
        "money", aliases=["$", "dollars", "shekels"],
        help="CLI analogs of webpages to monitor your balance and billing.")
    subparsers.add_parser(
        "prices", help="Print prices, works without login.")

    return parser.parse_args()


def main():
    args = parse_args()

    if args.json:
        global global_option_json
        global_option_json = True

    read_config_file()
    cli_command(args.command, args)


if __name__ == "__main__":
    main()
