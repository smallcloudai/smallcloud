import os, sys, json, time, subprocess
import urllib
import urllib.request
import pandas


v1_url = "https://staging.smallcloud.ai/v1/"


global_option_dryrun = False
global_option_verbose = False
global_option_json = False


# prefix command with dry=1 or verbose=1

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


def fetch_json(url):
    t0 = time.time()
    j = json.loads(urllib.request.urlopen(url).read())
    t1 = time.time()
    print_if_appropriate("%0.1fs %s" % (t1 - t0, url))
    return j


def code_root():
    p = os.path.dirname(__file__)
    while 1:
        if os.path.exists(p + "/smallcloud/smallcloud/__main__.py"):
            break
        if p == os.path.dirname(p):
            assert 0, "cannot find code root, started from %s" % __file__
        p = os.path.dirname(p)
    print_if_appropriate("code root detected at: %s" % p)


def command_nodes(*args):
    nodes_json = fetch_json(v1_url + "nodes")
    print_table(nodes_json)


def command_free(*args):
    free_json = fetch_json(v1_url + "free")
    print_table(free_json)


def command_scheduled(*args):
    free_json = fetch_json(v1_url + "scheduled")
    print_table(free_json)


def command_upload_code(*args, **kwargs):
    root = code_root()
    upload_dest = []
    user = kwargs.get("user", "user")
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
            "rsync", "-rpl", "-c", "--itemize-changes", ".", f"{dest['user']}@{dest['ip']}:code", "--filter=:- .gitignore", "--exclude=.git",
            "-e", f"ssh -p {dest['port']} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
            ]
        r = run(cmd, cwd=root, stdout=sys.stdout, stderr=sys.stderr)
        assert r==0, r


def run_command(command, *args, **kwargs):
    if command in ["list", "jobs"]:
        #  jobs_json = urllib.request.urlopen(v1_url + "jobs").read()
        pass

    elif command == "nodes":
        command_nodes()

    elif command == "free":
        command_free()

    elif command == "scheduled":
        command_scheduled()

    # elif command == "ssh":
    #     assert len(jobs) == 1
    #     j = jobs[0]
    #     nodes = version0.nodes_from_job(j)
    #     n0 = nodes[0]
    #     cmd = [
    #         "/usr/bin/ssh",
    #         "user@%s" % n0.addr,
    #         "-p", "%i" % n0.port,
    #         "-o", "StrictHostKeyChecking=no",
    #         "-o", "UserKnownHostsFile=/dev/null",
    #         # "-v",
    #         ]
    #     print("ssh", " ".join(cmd))
    #     os.execv("/usr/bin/ssh", cmd)

    elif command == "upload-code":
        command_upload_code(*args, **kwargs)

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
    kwargs = {}
    if args.user:
        kwargs["user"] = args.user
    run_command(*args.command, **kwargs)
