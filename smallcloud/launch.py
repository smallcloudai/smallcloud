import os, time, re, json, requests, termcolor, functools
from typing import Optional, List, Dict, Any, Union, Callable
import cloudpickle
from smallcloud import config, call_api, ssh_commands


MAX_UPLOAD_SIZE = 25*1024*1024


def upload_file(fn: str):
    config.read_config_file()
    size = os.path.getsize(fn)
    if size > MAX_UPLOAD_SIZE:
        raise Exception("Maximum archive size is %0.1fM, your code %0.1fM" % (MAX_UPLOAD_SIZE/1024/1024, size/1024/1024))
    url = config.v1_url + "task-file-upload"
    headers = config.account_and_secret_key_headers()
    files = {
        'file1': (os.path.basename(fn), open(fn, 'rb'), 'application/zip'),
    }
    print(url, "POST", os.path.basename(fn))
    r = requests.post(url, files=files, headers=headers)
    if r.status_code != 200:
        print("HTTP STATUS", r.status_code)
        quit(1)
    j = json.loads(r.text)
    if j["retcode"] != "OK":
        print(termcolor.colored(j["retcode"], "red"), j["human_readable_message"])
        quit(1)
    return j["upload_id"]


@functools.lru_cache()
def cached_code_to_zip():
    from smallcloud import code_to_zip
    return code_to_zip()


def launch_task(
    task_name: str,
    training_function: Union[Callable, str],
    args: List[Any] = [],
    kwargs: Dict[str, Any] = {},
    gpu_type="a5000",  # or more specifically cluster/gpu_type, "ant/a5000"
    gpus: int = 0,
    shutdown: str = "auto",  # "always", "never", "auto" doesn't shutdown if there's an error so you can look at the logs.
    nice: int = 1,  # 0 preempts others, 1 normal, 2 low
    os_image: str = "",
    env: Dict[str, str] = {},
    offline_code_zip: bool = False,
    call_function_directly: Optional[bool] = None,
):
    if call_function_directly or (call_function_directly is None and config.already_running_in_cloud):
        for k, v in env.items():
            os.environ[k] = v
        os.environ["TASK_NAME"] = task_name
        training_function(*args, **kwargs)
        return
    config.read_config_file()
    os.makedirs("/tmp/smc-temp", exist_ok=True)
    pickle_filename = f"/tmp/smc-temp/pickle-call-{task_name}.pkl"
    cloudpickle.dump({
        "training_function": training_function,
        "args": args,
        "kwargs": kwargs,
        "shutdown": shutdown,
        "env": {"TASK_NAME": task_name, **env},
        }, open(pickle_filename, "wb"))
    post_json = {
    "task_name": task_name,
    "tenant_image": os_image,
    "gpu_type": gpu_type,
    "gpu_min": int(gpus),
    "gpu_max": int(gpus),
    "gpus_incr": 1,
    "nice": nice,
    }
    if offline_code_zip:
        post_json["file_pkl"] = upload_file(pickle_filename)
        post_json["file_zip"] = upload_file(cached_code_to_zip())
    else:
        zip_filename = cached_code_to_zip()

    ret = call_api.fetch_json(config.v1_url + "reserve", post_json, headers=config.account_and_secret_key_headers())
    call_api.pretty_print_response(ret)

    if offline_code_zip:
        return
    while 1:
        time.sleep(3)
        r = call_api.fetch_json(config.v1_url + "task-nodes", get_params={"task_name": task_name}, headers=config.account_and_secret_key_headers())
        if r["retcode"] == "WAIT":
            print("%s waiting for the task to be scheduled" % time.strftime("%Y%m%d %H:%M:%S"))
            continue
        nodes = r["nodes"]
        nodes_running = [(1 if x["status"]=="running" else 0) for x in nodes]
        print("%s started %i/%i nodes" % (time.strftime("%Y%m%d %H:%M:%S"), sum(nodes_running), len(nodes)))
        if sum(nodes_running) == len(nodes) and len(nodes) > 0:
            break
    def waitall(ps, doing):
        ret = [p.wait() for p in ps]
        if any(ret):
            print("There was an error %s" % doing)
            quit(1)
    if len(nodes) > 1:
        ps = [ssh_commands.command_ssh(n["hostname"], "./smc_multinode_setup", fire_off=True) for n in nodes]
        waitall(ps, "setting up /etc/hosts and ssh keys for multi node")
    ps = [ssh_commands.command_scp(zip_filename, n["hostname"] + ":code.7z", fire_off=True) for n in nodes[0:1]]
    waitall(ps, "copying code.7z to the first node")
    ps = [ssh_commands.command_ssh(n["hostname"], "./smc_unpack_code.py", fire_off=True) for n in nodes[0:1]]
    waitall(ps, "running smc_unpack_code.py on the first node. Try looking at \"s tail %s\"" % nodes[0]["hostname"])
    ps = [ssh_commands.command_scp(pickle_filename, n["hostname"] + ":", fire_off=True) for n in nodes]
    waitall(ps, "copying pickled startup function call")
