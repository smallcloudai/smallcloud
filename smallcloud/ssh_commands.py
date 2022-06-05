import os, sys, subprocess, termcolor
from smallcloud import config, code_root, call_api


def run(cmd, stdout=None, stderr=None, colorize="", **kwargs):
    # This function runs 'rsync' and 'ssh-keygen'
    # To debug, use:
    #  verbose=1 dry=1 s command
    verbose = int(os.environ.get("verbose", "0"))
    if not verbose:
        stdout = subprocess.DEVNULL if stdout is None else stdout
    stderr = stderr or subprocess.PIPE
    if not call_api.global_option_json:
        print(" ".join(cmd) if not colorize else termcolor.colored(" ".join(cmd), colorize))
    dry = int(os.environ.get("dry", "0"))
    if dry:
        return 0
    completed_process = subprocess.run(cmd, stdout=stdout, stderr=stderr, **kwargs)
    if completed_process.returncode != 0:
        print("RETCODE: %s" % completed_process.returncode)
    if completed_process.stderr and (verbose or completed_process.returncode != 0):
        print("STDERR: %s" % completed_process.stderr.decode("utf-8"))
    return completed_process.returncode


def fetch_sshables():
    sshables = call_api.fetch_json(config.v1_url + "list-ssh-able", headers=config.account_and_secret_key_headers())
    known_hosts = []
    for rec in sshables:
        if rec["ed25519"].startswith("ssh-ed25519"):
            known_hosts.append("[%s]:%i %s" % (rec['ssh_addr'], rec['ssh_port'], rec['ed25519']))
    return sshables, known_hosts


def save_known_hosts(known_hosts):
    with open(config.known_hosts_file, "wt") as f:
        f.write("\n".join(known_hosts) + "\n")
    os.chmod(config.known_hosts_file, 0o600)


def add_ssh_identity_if_exists(ssh_cmdline):
    if os.path.exists(config.ssh_rsa_id_file):
        ssh_cmdline.extend(["-i", config.ssh_rsa_id_file])


def command_ssh(user_at_name, *args, fire_off=False):
    if "@" not in user_at_name:
        computer_name = user_at_name
        user = "user"
    else:
        user, computer_name = user_at_name.split("@")
    closest_match = None
    closest_match_dist = 1e10
    sshables, known_hosts = fetch_sshables()
    import difflib
    right_rec = None
    for rec in sshables:
        if rec["name"] == computer_name:
            if not rec["ed25519"]:
                print("'%s' is not ready" % rec["name"])
                return False
            right_rec = rec
        dist = difflib.SequenceMatcher(None, rec["name"], computer_name).ratio()
        if dist > 0.8 and dist < closest_match_dist:
            closest_match = rec
            closest_match_dist = dist
    if right_rec is None:
        call_api.print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        if closest_match is not None:
            print("Did you mean \"%s\"?" % closest_match["name"])
        return
    cmd = [
        "ssh",
        "%s@%s" % (user, right_rec['ssh_addr']),
        "-p", "%i" % right_rec['ssh_port'],
    ]
    if right_rec["ed25519"].startswith("ssh-ed25519"):  # Ether way strict checking is on!
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    cmd.extend(args)
    if fire_off:
        # return "a promise" client can wait on
        green_starts = -len(args)
        print(" ".join(cmd[:green_starts]) + " " + termcolor.colored(" ".join(cmd[green_starts:]), "green"))
        return subprocess.Popen(cmd)
    else:
        # this replaces the current process with scp
        print(" ".join(cmd))
        os.execv("/usr/bin/ssh", cmd)


def command_scp(*args, fire_off=False):
    remote_at = None
    for i in range(len(args)):
        if args[i].find(":") != -1:
            print("Re-writing \"%s\" as a remote location" % args[i])
            remote_at = i
            break
    if remote_at is None:
        print("Not clear which parameter refers to a remote location, this is detected by the presence of a colon \":\"")
        print("Examples:")
        print("s scp local_file1 job:remote_file")
        print("s scp \"user@job:remote_file*.txt\" local_folder/")
        quit(1)
    remote_location = args[remote_at]
    if "@" in remote_location:
        user, computer_name_colon_file = remote_location.split("@")
    else:
        user = "user"
        computer_name_colon_file = remote_location
    computer_name, path = computer_name_colon_file.split(":")
    right_rec = None
    sshables, known_hosts = fetch_sshables()
    for rec in sshables:
        if rec["name"] == computer_name:
            if not rec["ed25519"]:
                print("'%s' is not ready" % rec["name"])
                return False
            right_rec = rec
    if right_rec is None:
        call_api.print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        quit(1)
    cmd = ["scp", "-P", "%i" % right_rec['ssh_port']]
    if right_rec["ed25519"].startswith("ssh-ed25519"):
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    for i, a in enumerate(args):
        if i == remote_at:
            cmd.append("%s@%s:%s" % (user, right_rec['ssh_addr'], path))
        else:
            cmd.append(a)
    if fire_off:
        # return "a promise" client can wait on
        print(termcolor.colored(" ".join(cmd), "green"))
        return subprocess.Popen(cmd)
    else:
        # this replaces the current process with scp
        print(" ".join(cmd))
        os.execv("/usr/bin/scp", cmd)


def command_upload_code(*args):
    coderoot = code_root.detect_code_root()
    init = False
    if "--init" in args:
        init = True
        args = [x for x in args if x != "--init"]
    if len(args) == 0:
        print("Please specify computers to upload your code, for example \"myjob05*\", also try \"s list\".")
        quit(1)
    sshables, known_hosts = fetch_sshables()
    save_known_hosts(known_hosts)
    upload_dest = []
    upload_user = []
    for j in args:
        if "@" in j:
            user, computer_name = j.split("@")
        else:
            user = "user"
            computer_name = j
        for rec in sshables:
            import fnmatch
            if fnmatch.fnmatch(rec["name"], computer_name):
                if not rec["ed25519"]:
                    print("'%s' is not ready" % rec["name"])
                    return False
                upload_dest.append(rec)
                upload_user.append(user)
    call_api.print_if_appropriate("Uploading code to:")
    call_api.print_table(upload_dest, omit_for_brevity="ed25519")
    for rec, user in zip(upload_dest, upload_user):
        # "-u" update based on modification time
        # "-c" update based on checksum, not date, because git might clone newer files than your modified ones
        # "--delete" -- nice to have, but has unexpected effects
        ssh_cmd = [
            "ssh",
            "-p", "%i" % rec["ssh_port"],
        ]
        if rec["ed25519"].startswith("ssh-ed25519"):
            add_ssh_identity_if_exists(ssh_cmd)
            ssh_cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        cmd = [
            "rsync", "-rpl", "-c", "--itemize-changes", coderoot, f"{user}@{rec['ssh_addr']}:code/", "--filter=:- .gitignore", "--exclude=.git",
            "-e", " ".join(ssh_cmd),
            ]
        r = run(cmd, stdout=sys.stdout, stderr=sys.stderr, colorize="green")
        assert r==0, r
        if init:
            ssh_cmd.extend([f"{user}@{rec['ssh_addr']}", "cd code && bash .smc_code_root.sh"])
            r = run(ssh_cmd, stdout=sys.stdout, stderr=sys.stderr, colorize="green")
            assert r==0, r
    return True


def command_ssh_keygen(*args):
    jobs_for_warning = call_api.fetch_json(config.v1_url + "jobs", headers=config.account_and_secret_key_headers())
    jobs_running = [x for x in jobs_for_warning if x["ts_finished"] == 0]
    if len(jobs_running) > 0:
        print(f"You have {len(jobs_running)} jobs running. All ssh-based commands from this computer will start to use a new \"-i {config.ssh_rsa_id_file}\" identity file, this might prevent you from logging in to these running machines.")
        quit(1)
    try:
        os.unlink(config.ssh_rsa_id_file)
    except FileNotFoundError:
        pass
    r = run(["ssh-keygen", "-f", config.ssh_rsa_id_file, "-N", "", *args])
    assert r==0, r
    resp = call_api.fetch_json(
        config.v1_url + "ssh-public-key-upload",
        post_json={"ssh_public_key": open(config.ssh_rsa_id_file + ".pub").read()},
        headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(resp)


def command_ssh_key_upload(*args):
    if len(args) != 1:
        print("Please specify a file to upload, such as ~/.ssh/id_rsa.pub\n(do this if you want ssh without -i option to work, for a dedicated key use \"s ssh-keygen\")")
        quit(1)
    resp = call_api.fetch_json(
        config.v1_url + "ssh-public-key-upload",
        post_json={"ssh_public_key": open(os.path.expanduser(args[0])).read()},
        headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(resp)
