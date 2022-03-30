import os, sys, json, time, subprocess, termcolor
from smallcloud import config, code_root, call_api

# This file runs on "s" in command line.


def printhl(s):
    print(termcolor.colored(s, attrs=["bold"]))


def print_help():
    print("This is a command line tool to use Small Magellanic Cloud AI Ltd services.")
    print("Homepage for this tool:")
    print("    https://github.com/smallcloudai/smallcloud")
    print("Commands:")
    printhl("s free")
    print("      Print number of free GPUs, works without login.")
    printhl("s prices")
    print("      Print prices, works without login.")
    printhl("s login")
    print("      Interactive login using your web browser.")
    printhl("s list")
    print("      Prints your jobs, working and finished.")
    printhl("s reserve <gpu_type> <gpu_count> <job_name>")
    print("      Reserve GPUs, start the job. Valid gpu_count values are 1, 2, 4, 8, 16, 32, 64.")
    print("      Starting from 16, multiple VMs will be launched.")
    print("      If the job cannot start immediately, it will be queued.")
    printhl("s delete <job_name>")
    print("      Delete the job. Use \"experiment05*\" syntax to delete several jobs.")
    printhl("s ssh <job_name> [<any-ssh-args>]")
    print("      SSH into the job. By default the user is \"user\". You can use \"otheruser@jobname\" syntax if you created more users.")
    printhl("s scp <local_file> <job_name>:<remote_file> [<any-scp-args>]")
    print("      Copy a file.")
    printhl("s upload-code <job_name>")
    print("      Upload your source code using rsync.")
    print("      Use \"experiment05*\" syntax to upload to several jobs.")
    print("      Remote destination is hardcoded as \"/home/user/code/\".")
    printhl("s ssh-keygen")
    print("      Generate a new SSH keypair and upload the public part.")
    printhl("s ssh-upload")
    print("      If you prefer, you can upload this computer's public key.")
    printhl("s billing")
    printhl("s billing-detailed")
    printhl("s money")
    print("      CLI analogs of webpages to monitor your balance and billing.")


def run(cmd, stdout=None, stderr=None, **kwargs):
    # This function runs 'rsync' and 'ssh-keygen'
    # To debug, use:
    #  verbose=1 dry=1 s command
    verbose = int(os.environ.get("verbose", "0"))
    if not verbose:
        stdout = subprocess.DEVNULL if stdout is None else stdout
    stderr = stderr or subprocess.PIPE
    if not call_api.global_option_json:
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


def command_login(*args):
    assert len(args) <= 1
    print("Please open this link in your browser:\n")
    print(termcolor.colored(config.v1_url.replace("/v1/", "/cli-login"), attrs=["bold"]))
    ticket = input("\nand copy-paste a response here: ")
    resp = call_api.fetch_json(config.v1_url + "cli-login-response", get_params={"ticket": ticket})
    os.makedirs(config.config_dir, exist_ok=True)
    with open(config.config_file, "w") as f:
        f.write(json.dumps({
            "account_name": resp["account_name"],
            "expires_ts": (resp["expires_ts"] if "expires_ts" in resp else 365*24*60*60 + time.time()),
            "secret_api_key": resp["secret_api_key"],
            }, indent=4))
    os.chmod(config.config_file, 0o600)
    print("\Login successful: %s" % resp["account_name"])
    print("Account name and the Secret API Key were stored in %s" % config.config_file)
    print("Try this:")
    print(termcolor.colored("s list", attrs=["bold"]))
    print(termcolor.colored("s free", attrs=["bold"]))
    print(termcolor.colored("s reserve a5000 4 myexperiment00", attrs=["bold"]))


def command_logout():
    if not config.username:
        print("You are not logged in")
        return
    os.remove(config.config_file)
    print("Logged out")



def command_free():
    free_json = call_api.fetch_json(config.v1_url + "free", headers=config.account_and_secret_key_headers())
    call_api.print_table(free_json)


def command_reserve(*args):
    config.make_sure_have_login()
    # The only nontrivial command with options at this point:
    import argparse
    parser = argparse.ArgumentParser(description="Schedule your GPU task.")
    subparsers = parser.add_subparsers()
    parser_reserve = subparsers.add_parser("reserve")
    parser_reserve.add_argument("gpu_type", help="GPU to reserve")
    parser_reserve.add_argument("count", type=int, help="Number of GPUs")
    parser_reserve.add_argument("job_name", help="Name of the experiment")
    parser_reserve.add_argument("--os", help="Operating system")
    args = parser.parse_args(("reserve",) + args)
    gpu_min = args.count
    post_json = {
        "task_name": args.job_name,
        "gpu_type": args.gpu_type,
        "gpu_min": int(gpu_min),
        }
    if args.os:
        post_json["tenant_image"] = args.os
    ret_json = call_api.fetch_json(config.v1_url + "reserve", post_json, headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(ret_json)


def command_jobs():
    config.make_sure_have_login()
    resp = call_api.fetch_json(config.v1_url + "jobs", headers=config.account_and_secret_key_headers())
    day_ago = time.time() - 24*3600
    if resp == []:
        print("There are no jobs yet. You can start one using:\n" + termcolor.colored("s reserve a5000 4 myexperiment00-seed0", attrs=["bold"]))
        return
    finished_less_than_day_ago = [x for x in resp if x["ts_finished"] == 0 or x["ts_finished"] > day_ago]
    hidden = len(resp) - len(finished_less_than_day_ago)
    if hidden:
        print(termcolor.colored("Finished more than a day ago: %i" % hidden, "white"))
    call_api.print_table(finished_less_than_day_ago, ["cluster_name", "tenant_image", "ts_placed", "gpu_type", "gpus_min", "gpus_max", "gpus_incr", "nice", "ed25519"])


def command_delete(*task_names):
    config.make_sure_have_login()
    for tname in task_names:
        resp = call_api.fetch_json(config.v1_url + "delete", get_params={"task_name": tname}, headers=config.account_and_secret_key_headers())
        call_api.pretty_print_response(resp)


def fetch_sshables():
    sshables = call_api.fetch_json(config.v1_url + "list-ssh-able", headers=config.account_and_secret_key_headers())
    known_hosts = []
    for rec in sshables:
        if rec["ed25519"]:
            known_hosts.append("[%s]:%i %s" % (rec['ssh_addr'], rec['ssh_port'], rec['ed25519']))
    return sshables, known_hosts


def save_known_hosts(known_hosts):
    with open(config.known_hosts_file, "wt") as f:
        f.write("\n".join(known_hosts) + "\n")
    os.chmod(config.known_hosts_file, 0o600)


def command_ssh(user_at_name, *args):
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
    if right_rec["ed25519"]:  # Ether way strict checking is on!
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    cmd.extend(args)
    print(" ".join(cmd))
    # this replaces the current process with ssh
    os.execv("/usr/bin/ssh", cmd)


def command_scp(*args):
    remote_at = None
    for i in range(len(args)):
        if args[i].find(":") != -1:
            print("Re-writing \"%s\" as a remote location" % args[i])
            remote_at = i
            break
    if remote_at is None:
        print("Not clear which parameter refers to a remote location, this is detected by presence of a colon \":\"")
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
            right_rec = rec
    if right_rec is None:
        call_api.print_table(sshables)
        print("Computer \"%s\" wasn't found." % computer_name)
        quit(1)
    cmd = ["scp", "-P", "%i" % right_rec['ssh_port']]
    if right_rec["ed25519"]:
        save_known_hosts(known_hosts)
        cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        add_ssh_identity_if_exists(cmd)
    for i, a in enumerate(args):
        if i == remote_at:
            cmd.append("%s@%s:%s" % (user, right_rec['ssh_addr'], path))
        else:
            cmd.append(a)
    print(" ".join(cmd))
    # this replaces the current process with scp
    os.execv("/usr/bin/scp", cmd)


def command_upload_code(*args):
    coderoot = code_root.detect_code_root()
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
        if rec["ed25519"]:
            add_ssh_identity_if_exists(ssh_cmd)
            ssh_cmd.extend(["-o", "UserKnownHostsFile=%s" % config.known_hosts_file])
        cmd = [
            "rsync", "-rpl", "-c", "--itemize-changes", coderoot, f"{user}@{rec['ssh_addr']}:code/", "--filter=:- .gitignore", "--exclude=.git",
            "-e", " ".join(ssh_cmd),
            ]
        r = run(cmd, stdout=sys.stdout, stderr=sys.stderr)
        assert r==0, r


def command_nodes():
    nodes_json = call_api.fetch_json(config.v1_url + "nodes", headers=config.account_and_secret_key_headers())
    call_api.print_table(nodes_json)


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


def command_ssh_upload(*args):
    if len(args) != 1:
        print("Please specify a file to upload, such as ~/.ssh/id_rsa.pub\n(do this if you want ssh without -i option to work, for a dedicated key use \"s ssh-keygen\")")
        quit(1)
    resp = call_api.fetch_json(
        config.v1_url + "ssh-public-key-upload",
        post_json={"ssh_public_key": open(os.path.expanduser(args[0])).read()},
        headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(resp)


def add_ssh_identity_if_exists(ssh_cmdline):
    if os.path.exists(config.ssh_rsa_id_file):
        ssh_cmdline.extend(["-i", config.ssh_rsa_id_file])


def command_promo(*args):
    if len(args) == 0:
        print("This command applies a promo code (might add money to your account).")
        return
    assert len(args) == 1
    resp = call_api.fetch_json(config.v1_url + "apply-promo", get_params={"code": args[0]}, headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(resp)


def command_billing(subcmd):
    resp = call_api.fetch_json(config.v1_url + subcmd, headers=config.account_and_secret_key_headers())
    if subcmd == "money":
        print(json.dumps(resp, indent=2))
    else:
        call_api.print_table(resp)


def command_prices():
    resp = call_api.fetch_json(config.v1_url + "prices")
    print(resp)


def cli_command(command, *args):
    if command == "free":
        command_free()

    elif command == "login":
        command_login(*args)

    elif command == "logout":
        command_logout()

    elif command == "reserve":
        command_reserve(*args)

    elif command in ["list", "jobs"]:
        command_jobs()

    elif command in ["delete", "remove"]:
        command_delete(*args)

    elif command == "upload-code":
        command_upload_code(*args)

    elif command == "nodes":
        command_nodes()

    elif command == "ssh":
        command_ssh(*args)

    elif command == "scp":
        command_scp(*args)

    elif command == "ssh-keygen":
        command_ssh_keygen(*args)

    elif command == "ssh-upload":
        command_ssh_upload(*args)

    elif command == "promo":
        command_promo(*args)

    elif command == "billing":
        command_billing("billing-short")

    elif command == "billing-detailed":
        command_billing("billing-detailed")

    elif command in ["$", "money", "dollars"]:
        command_billing("money")

    elif command == "prices":
        command_prices()

    elif command == "tail":
        command_ssh(*args + ("tail -n 1000 -f output.log",))

    else:
        print_help()
        print("Unknown command:", command)
        quit(1)


def main():
    if "--json" in sys.argv:
        call_api.global_option_json = True
        sys.argv.remove("--json")
    if len(sys.argv) < 2:
        print_help()
        quit(0)
    config.read_config_file()
    cli_command(sys.argv[1], *sys.argv[2:])


if __name__=="__main__":
    main()
