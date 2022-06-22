import json, re, requests, time, datetime, termcolor, multiprocessing, copy
from typing import Dict, Any, List, Optional
import traces


url_base = "https://inference.smallcloud.ai/infengine-v1/"


def model_guid_allowed_characters(name):
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


def validate_description_dict(
    infeng_instance_guid: str,
    account: str,
    model: str,
    B: int,
    T: int,
    encoding_name: str,
    max_thinking_time: int,
):
    return {
        "infmod_guid": model_guid_allowed_characters(infeng_instance_guid),
        "account": account,
        "model": model,
        "B": B,
        "T": T,
        "encoding_name": encoding_name,
        "engine_started_ts": int(time.time()),
        "ts_batch_started": 0,
        "ts_batch_finished": 0,
        "max_thinking_time": max_thinking_time,
    }


def completions_wait_batch(req_session, my_desc, verbose=False):
    t0 = time.time()
    url = url_base + "completions-wait-batch"
    resp = None
    try:
        resp = req_session.post(url, json=my_desc)
        json_resp = resp.json()
    except Exception as e:
        traces.log("fetch batch failed: %s" % str(e))
        if resp is not None:
            traces.log("server response text:\n%s" % (resp.text,))
        return "ERROR", []
    if resp.status_code != 200:
        traces.log("%s status_code %i %s" % (url, resp.status_code, resp.text))
        return "ERROR", []
    t1 = time.time()
    hms = datetime.datetime.now().strftime("%H%M%S.%f")
    traces.log("%s %0.1fms %s %s" % (hms, 1000*(t1 - t0), url, termcolor.colored(json_resp["retcode"], "green")))
    if verbose:
        traces.log("%s %s" % (url, json.dumps(json_resp, indent=4)))
    return json_resp["retcode"], json_resp.get("batch", [])


def completions_upload_result(
    q,
    description_dict: Dict[str, Any],
    original_batch: Dict[str, Any],
    ts_batch_started: float,
    ts_batch_finished: float,
    status: str,              # "in_progress", "completed"
    idx_updated: List[int],   # batch indexes where you have progress
    text: List[str],          # updated text in those indexes
    finish_reason: List[str], # empty if not finished yet
    tokens: Optional[List[int]] = None,
):
    upload_dict = copy.deepcopy(description_dict)
    upload_dict["ts_batch_started"] = ts_batch_started
    upload_dict["ts_batch_finished"] = ts_batch_finished
    upload_dict["progress"] = {
        original_batch[b]["id"]: {
            "id": original_batch[b]["id"],
            "object": "text_completion",
            "choices": [
                {
                    "index": 0,
                    "text": text[b],
                    "tokens": ([int(t) for t in tokens[b]] if tokens is not None else None),
                    "logprobs": None,
                    "finish_reason": finish_reason[b]
                },
            ],
            "status": status,
        }
        for b in idx_updated
    }
    q.put(copy.deepcopy(upload_dict))
    return upload_dict


def start_separate_upload_process():
    q = multiprocessing.Queue()
    proc = multiprocessing.Process(
        target=_upload_results_loop,
        args=(q,),
        )
    proc.start()
    return proc, q


def stop_separate_upload_process(proc, q):
    q.put(dict(exit=1))
    proc.join()


def _upload_results_loop(q: multiprocessing.Queue):
    req_session = requests.Session()
    exit_flag = False
    while not exit_flag:
        upload_dict = q.get()
        if "exit" in upload_dict:
            exit_flag = True
        t1 = time.time()
        while 1:
            if upload_dict.get("ts_batch_finished", 0) > 0:
                # Send ASAP
                break
            maybe_pile_up = q.get() if not q.empty() else None
            if maybe_pile_up is None:
                if time.time() < t1 + 0.5:
                    # Normally send every ~0.5 seconds
                    time.sleep(0.1)
                    continue
                else:
                    break
            if "exit" in maybe_pile_up:
                exit_flag = True
            if "progress" in maybe_pile_up:
                upload_dict["progress"].update(maybe_pile_up["progress"])
                upload_dict["ts_batch_finished"] = maybe_pile_up["ts_batch_finished"]

        url = url_base + "completion-upload-results"
        resp = None
        try:
            t2 = time.time()
            resp = req_session.post(url, json=upload_dict)
            t3 = time.time()
            hms = datetime.datetime.now().strftime("%H%M%S.%f")
            traces.log("%s %0.1fms %s %s" % (hms, 1000*(t3 - t2), url, termcolor.colored(resp.json()["retcode"], "green")))
            if resp.status_code != 200:
                traces.log("post response failed: %i %s" % (resp.status_code, resp.text))
        except Exception as e:
            traces.log("post response failed: %s" % str(e))
            if resp is not None:
                traces.log("server response text:\n%s" % (resp.text,))
