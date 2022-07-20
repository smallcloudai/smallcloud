import os, sys, requests, time, json
from typing import Union, Tuple, Generator, Optional


base_url = "https://inference.smallcloud.ai/v1/"


class APIConnectionError(Exception):
    pass


_dsess: Optional[requests.Session] = None


def default_session() -> requests.Session:
    global _dsess
    if _dsess is None:
        if "SMALLCLOUD_API_KEY" not in os.environ:
            raise ValueError("Please either set SMALLCLOUD_API_KEY environment variable or create requests session manually.")
        _dsess = requests.Session()
        _dsess.headers.update({
            "Authorization": "Bearer %s" % os.environ["SMALLCLOUD_API_KEY"],
        })
    return _dsess


def nlp_model_call(
    endpoint: str,
    model: str,
    *,
    req_session: Optional[requests.Session]=None,
    max_tokens: int,
    stream: bool=False,
    temperature: float,
    top_p: Optional[float]=None,
    top_n: Optional[int]=None,
    # TODO stop sequences
    verbose: int=0,
    **pass_args
) -> Union[Tuple[str, str], Generator[Tuple[str, str], None, None]]:
    req_session = req_session or default_session()
    assert isinstance(req_session, requests.Session)
    url = base_url + endpoint
    data = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
        **pass_args,
    }
    if top_p is not None:
        data["top_p"] = top_p
    if top_n is not None:
        data["top_n"] = top_n
    if verbose > 1:
        print("POST %s" % (data,))
    resp = None
    try:
        t0 = time.time()
        if not stream:
            resp = req_session.post(url, json=data)
        else:
            resp = req_session.post(url, json=data, stream=True)
        t1 = time.time()
        if verbose > 0:
            print("%0.1fms %s" % (1000*(t1 - t0), url))
    except Exception as e:
        if resp is not None:
            raise APIConnectionError("completions() json parse failed: %i\n%s" % (resp.status_code, resp.text))
        else:
            raise APIConnectionError("completions() failed: %s" % str(e))
    if resp.status_code != 200:
        raise APIConnectionError("status=%i, server returned:\n%s" % (resp.status_code, resp.text))
    if stream:
        def _streamer(resp):
            for line in resp.iter_lines(chunk_size=1):
                if line.startswith(b"data: {"):
                    j = json.loads(line[6:].decode("utf-8"))
                    yield j
                if line.startswith(b"data: [DONE]"):
                    return
        return _streamer(resp)
    if verbose > 1:
        print("RESPONSE", resp.text)
    try:
        json_resp = resp.json()
    except Exception as e:
        if resp is not None:
            raise APIConnectionError("completions() json parse failed: %i\n%s" % (resp.status_code, resp.text))
        else:
            raise APIConnectionError("completions() failed: %s" % str(e))
    return json_resp
