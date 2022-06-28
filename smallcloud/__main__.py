import os, sys, json, time, termcolor
from smallcloud import config, call_api, ssh_commands

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
    print("      Add --init option to run \"/home/user/code/.smc_code_root.sh\" after the upload is completed.")
    printhl("s ssh-keygen")
    print("      Generate a dedicated SSH keypair and upload the public part.")
    printhl("s ssh-key-upload")
    print("      If you prefer, you can upload this computer's public key or any other key.")
    printhl("s billing")
    printhl("s billing-detailed")
    printhl("s money")
    print("      CLI analogs of webpages to monitor your balance and billing.")


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
    print("Login successful: %s" % resp["account_name"])
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
    parser_reserve.add_argument("--force-node", help=argparse.SUPPRESS)
    args = parser.parse_args(("reserve",) + args)
    gpus_min = args.count
    post_json = {
        "task_name": args.job_name,
        "gpu_type": args.gpu_type,
        "gpus_min": int(gpus_min),
        "force_node": args.force_node,
        }
    if args.os:
        post_json["tenant_image"] = args.os
    ret_json = call_api.fetch_json(config.v1_url + "reserve", post_json, headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(ret_json)


def command_jobs(*args):
    config.make_sure_have_login()
    resp = call_api.fetch_json(config.v1_url + "jobs", headers=config.account_and_secret_key_headers())
    day_ago = time.time() - 24*3600
    if resp == []:
        print("There are no jobs yet. You can start one using:\n" + termcolor.colored("s reserve a5000 4 myexperiment00-seed0", attrs=["bold"]))
        return
    import argparse
    parser = argparse.ArgumentParser(description="List your jobs.")
    parser.add_argument("--all", action="store_true", help="Show all jobs, not only those that are finished less than a day ago.")
    args = parser.parse_args(args)
    if args.all:
        finished_less_than_day_ago = resp
    else:
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


def command_nodes():
    nodes_json = call_api.fetch_json(config.v1_url + "nodes", headers=config.account_and_secret_key_headers())
    call_api.print_table(nodes_json)


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
        command_jobs(*args)

    elif command in ["delete", "remove"]:
        command_delete(*args)

    elif command == "nodes":
        command_nodes()

    elif command in ["upload-code", "code-upload"]:
        ssh_commands.command_upload_code(*args)

    elif command == "ssh":
        ssh_commands.command_ssh(*args)

    elif command == "scp":
        ssh_commands.command_scp(*args)

    elif command == "tail":
        ssh_commands.command_ssh(*args + ("tail -n 1000 -f output.log",))

    elif command == "ssh-keygen":
        ssh_commands.command_ssh_keygen(*args)

    elif command == "ssh-key-upload":
        ssh_commands.command_ssh_key_upload(*args)

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
