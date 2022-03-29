import os, json, requests, termcolor
from typing import Optional, List, Dict, Any, Union, Callable
import cloudpickle
from smallcloud import config


MAX_UPLOAD_SIZE = 5*1024*1024


def upload_file(fn: str):
    config.read_config_file()
    size = os.path.getsize(fn)
    if size > MAX_UPLOAD_SIZE:
        raise Exception("Maximum archive size is %0.1fM, your code %0.1fM" % (MAX_UPLOAD_SIZE/1024/1024, size/1024/1024))
    url = config.v1_url + "task-file-upload"
    headers = config.account_and_secret_key_headers()
    files = {
        'file1': (os.path.basename(fn), open(fn, 'rb'), 'application/zip'),
        'file2': (os.path.basename(fn), open(fn, 'rb'), 'application/zip'),
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
    print(j)
    return j["upload_id"]


def code_upload(zip_fn: Optional[str] = None):
    if zip_fn is None:
        from smallcloud import code_to_zip
        zip_fn = code_to_zip()
    return upload_file(zip_fn)


def launch_task(
    training_function: Union[Callable, str],
    task_name: str,
    args: List[Any] = [],
    kwargs: Dict[str, Any] = {},
    code_zip: Optional[str] = None,
    gpu_type="a5000",
    gpus: int = 0,
    # shutdown="auto",
    # gpu_per_process: int = 1,
    # gpu_bond: int = 1,
    # cluster: str = "default",
    # priority: int = 1,  # 0 preempts others, 1 normal, 2 low
):
    os.makedirs("/tmp/smc-temp", exist_ok=True)
    pickle_filename = f"/tmp/smc-temp/pickle-call-{task_name}.pkl"
    cloudpickle.dump(training_function, open(pickle_filename, "wb"))
    pickle_upload_id = upload_file(pickle_filename)
