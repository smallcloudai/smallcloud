import os, json, time


v1_url = "https://www.smallcloud.ai/v1/"
if os.environ.get("staging"):
    v1_url = v1_url.replace("www", "staging")
if os.environ.get("local"):
    v1_url = v1_url.replace("www", "local")

config_dir = os.path.expanduser("~/.config/smallcloud.ai")
config_file = config_dir + "/cli_config"
ssh_rsa_id_file = config_dir + "/dedicated_ssh_rsa_id"
known_hosts_file = config_dir + "/known_hosts"
username = None
secret_api_key = None
already_running_in_cloud = os.path.exists("/etc/profile.d/50-smc.sh")


def read_config_file():
    if not os.path.exists(config_file):
        return
    try:
        with open(config_file, "r") as f:
            config = json.loads(f.read())
    except ValueError:
        print("Empty or invalid config file: %s (delete it to relogin)" % config_file)
        quit(1)
    global username, secret_api_key
    if "expires_ts" in config and time.time() > config["expires_ts"] > 0:
        print("Your login credentials are expired, please re-login.")
    else:
        username = config["account_name"]
        secret_api_key = config["secret_api_key"]


def account_and_secret_key_headers():
    if not username:
        return {}   # some commands work without login
    return {
        "Authorization": "Bearer " + secret_api_key,
    }


def make_sure_have_login():
    if not username:
        print("Please login to complete this operation, try \"s login\"")
        quit(1)
