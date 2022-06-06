import json, time, termcolor
import urllib
import urllib.request
import urllib.error


def fetch_json(url, post_json=None, get_params=None, headers={}, ok_retcodes=[]):
    t0 = time.time()
    try:
        if get_params is not None:
            url += "?" + urllib.parse.urlencode(get_params)
        elif post_json is not None:
            print(json.dumps(post_json))
        req = urllib.request.Request(
            url,
            json.dumps(post_json).encode("utf-8") if post_json else None,
            {'Content-Type': 'application/json', **headers}
        )
        result = urllib.request.urlopen(req).read()
        t1 = time.time()
        print_if_appropriate("%0.2fs %s" % (t1 - t0, url))
    except urllib.error.URLError:
        print("ERROR %s" % (url))
        raise
    try:
        j = json.loads(result)
    except ValueError:
        print("Response from server is not a json:")
        print(result.decode("utf-8"))
        quit(1)
    if "retcode" in j and j["retcode"] not in (["OK"] + ok_retcodes):
        print(termcolor.colored(j["retcode"], "red"), j["human_readable_message"])
        quit(1)
    return j


def pretty_print_response(json):
    if isinstance(json, dict) and "retcode" in json:
        retcode = json["retcode"]
        color = "green" if retcode == "OK" else "red"
        print(termcolor.colored(retcode, color), json["human_readable_message"])
        return
    print(json)


global_option_json = False


def print_if_appropriate(*args):
    if not global_option_json:
        print(*args)


def print_table(resp, omit_for_brevity=[]):
    if global_option_json:
        print(json.dumps(resp, indent=4))
        return
    if len(resp) == 0:
        print("Empty result")
        return
    if isinstance(resp, dict):
        keys = sorted(resp.keys())
        assert isinstance(resp[keys[0]], dict)
        flatlist = [resp[k] for k in keys]
    elif isinstance(resp, list):
        flatlist = resp
    else:
        print("Server returned:\n%s" % str(resp))
        quit(1)
    def print_datetime(ts):
        if ts==0: return "-"
        full = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time()))):
            return time.strftime("%H:%M:%S", time.localtime(ts))
        if full.startswith(time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))):
            return time.strftime("%a %H:%M:%S", time.localtime(ts))
        return full
    import pandas   # is slow, don't import at the top of the file.
    df = pandas.DataFrame()
    for column in flatlist[0].keys():
        if column in omit_for_brevity:
            continue
        if not column.startswith("ts_") and not column.endswith("_ts"):
            df[column.upper()] = [x[column] for x in flatlist]
        else:
            df[column.upper()] = [print_datetime(x[column]) for x in flatlist]
    pandas.set_option('display.max_rows', None)
    print(df)

