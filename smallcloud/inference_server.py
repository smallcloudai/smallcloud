import sys, json, re, requests, time, datetime, termcolor, multiprocessing, copy, queue
from typing import Dict, Any, List, Optional, Set


url_base1 = "https://inference.smallcloud.ai/infengine-v1/"
url_base2 = "https://inference-backup.smallcloud.ai/infengine-v1/"
urls_to_try = [url_base1, url_base2]

urls_switch_n = 0
urls_switch_ts = time.time()


def log(*args):
    sys.stderr.write(" ".join([str(x) for x in args]) + "\n")
    sys.stderr.flush()


def url_get_the_best():
    global urls_switch_n, urls_switch_ts
    if time.time() > urls_switch_ts + 600:
        urls_switch_n = 0
    return urls_to_try[urls_switch_n]


def url_complain_doesnt_work():
    global urls_switch_n, urls_switch_ts
    urls_switch_n = (urls_switch_n + 1) % len(urls_to_try)
    urls_switch_ts = time.time()


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
    resp = None
    json_resp = None
    for attempt in range(5):
        url = url_get_the_best() + "completions-wait-batch"
        try:
            resp = req_session.post(url, json=my_desc, timeout=15)
            json_resp = resp.json()
        except requests.exceptions.ReadTimeout as e:
            t1 = time.time()
            log("%s %0.1fms %s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f"), 1000*(t1 - t0), url, termcolor.colored("TIMEOUT", "green")))
            url_complain_doesnt_work()
            continue
        except Exception as e:
            log("%s fetch batch failed: %s %s" % (url, str(type(e)), str(e)))
            # if resp is not None:
            #     log("server response text:\n%s" % (resp.text,))
            url_complain_doesnt_work()
            continue
        if resp.status_code != 200:
            log("%s status_code %i %s" % (url, resp.status_code, resp.text))
            url_complain_doesnt_work()
            continue
        break
    if json_resp is None:
        return "ERROR", []
    t1 = time.time()
    hms = datetime.datetime.now().strftime("%H:%M:%S.%f")
    log("%s %0.1fms %s %s" % (hms, 1000*(t1 - t0), url, termcolor.colored(json_resp["retcode"], "green")))
    if verbose:
        log("%s %s" % (url, json.dumps(json_resp, indent=4)))
    return json_resp["retcode"], json_resp.get("batch", [])


class UploadProxy:
    def __init__(self):
        multiprocessing.set_start_method("spawn")
        self.upload_q = multiprocessing.Queue()
        self.cancelled_q = multiprocessing.Queue()
        self.proc = multiprocessing.Process(
            target=_upload_results_loop,
            args=(self.upload_q, self.cancelled_q),
            name="upload_results",
            )
        self.proc.start()
        self._cancelled: Set[str] = set()

    def stop(self):
        if self.proc:
            self.upload_q.put(dict(exit=1))
            self.proc.join()
            self.proc = None

    def __del__(self):
        self.stop()

    def cancelled_reset(self):
        self._cancelled = set()

    def upload_result(
        self,
        description_dict: Dict[str, Any],
        original_batch: Dict[str, Any],
        ts_batch_started: float,
        ts_batch_finished: float,
        status: str,                  # "in_progress", "completed"
        idx_updated: List[int],       # batch indexes where you have progress
        files: List[Dict[str, str]],  # updated text in those indexes
        finish_reason: List[str],     # empty if not finished yet
        tokens: Optional[List[int]] = None,
        more_toplevel_fields: Optional[List[Dict[str, Any]]] = None,
        generated_tokens_n: Optional[List[int]] = None,
    ):
        upload_dict = copy.deepcopy(description_dict)
        upload_dict["ts_batch_started"] = ts_batch_started
        upload_dict["ts_batch_finished"] = ts_batch_finished
        progress = dict()
        for i, b in enumerate(idx_updated):
            progress[original_batch[b]["id"]] = {
                "id": original_batch[b]["id"],
                "object": "text_completion",
                "choices": [
                    {
                        "index": 0,
                        "files": files[i],
                        # "tokens": ([int(t) for t in tokens[b]] if tokens is not None else None),
                        "logprobs": None,
                        "finish_reason": finish_reason[i]
                    },
                ],
                "status": status,
                "more_toplevel_fields": (more_toplevel_fields[i] if more_toplevel_fields is not None else dict()),
                "generated_tokens_n": (generated_tokens_n[i] if generated_tokens_n is not None else 0),
            }
        upload_dict["progress"] = progress
        self.upload_q.put(copy.deepcopy(upload_dict))
        while not self.cancelled_q.empty():
            self._cancelled.add(self.cancelled_q.get())
        return self._cancelled

    def keepalive(self):
        self.upload_q.put(dict(keepalive=1))


def _upload_results_loop(upload_q: multiprocessing.Queue, cancelled_q: multiprocessing.Queue):
    req_session = requests.Session()
    exit_flag = False
    while not exit_flag:
        try:
            upload_dict = upload_q.get(timeout=600)
        except queue.Empty as e:
            log("%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f"), termcolor.colored("upload_results_loop timeout, exiting", "red")))
            exit_flag = True
            continue
        if "exit" in upload_dict:
            exit_flag = True
            break
        if "progress" not in upload_dict:
            continue
        t1 = time.time()
        while 1:
            if upload_dict.get("ts_batch_finished", 0) > 0:
                # Send ASAP
                break
            maybe_pile_up = upload_q.get() if not upload_q.empty() else None
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
        resp = None
        t2 = time.time()
        for _attempt in range(5):
            try:
                url = url_get_the_best() + "completion-upload-results"
                resp = req_session.post(url, json=upload_dict, timeout=2)
                j = resp.json()
            except requests.exceptions.ReadTimeout as e:
                t3 = time.time()
                log("%s %0.1fms %s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f"), 1000*(t3 - t2), url, termcolor.colored("TIMEOUT", "green")))
                url_complain_doesnt_work()
                continue
            except Exception as e:
                log("%s post response failed: %s" % (url, str(e)))
                #if resp is not None:
                #    log("server response text:\n%s" % (resp.text,))
                url_complain_doesnt_work()
                continue
            if resp.status_code != 200:
                log("%s post response failed: %i %s" % (url, resp.status_code, resp.text[:100]))
                url_complain_doesnt_work()
                continue
            break
        t3 = time.time()
        cancelled_n = 0
        if "cancelled" in j:
            for can in j["cancelled"]:
                cancelled_q.put(can)
                cancelled_n += 1
        log("%s %s %s %s %i uploaded, %i cancelled" % (datetime.datetime.now().strftime("%H:%M:%S.%f"),
            termcolor.colored("%0.1fms" % (1000*(t3 - t2),), "green"),
            url,
            termcolor.colored(j.get("retcode", -1), "green"),
            len(upload_dict["progress"]),
            cancelled_n,
            ))
