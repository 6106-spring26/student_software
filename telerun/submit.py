#!/usr/bin/env python

import argparse
import urllib
import urllib.parse
import urllib.request
import ssl
import os
import json
import traceback
import time
import base64

timeout = 120 # seconds

server_cert = """
-----BEGIN CERTIFICATE-----
MIID3DCCAsSgAwIBAgIUXJGRNZa7Zx/XYNvfwQm/FIXfPcUwDQYJKoZIhvcNAQEL
BQAwcjELMAkGA1UEBhMCVVMxFjAUBgNVBAgMDU1hc3NhY2h1c2V0dHMxEjAQBgNV
BAcMCUNhbWJyaWRnZTEeMBwGA1UECgwVTUlUIDYxMDYgQ291cnNlIFN0YWZmMRcw
FQYDVQQDDA4xNTcuMTgwLjU2LjE2NDAeFw0yNjAyMDQyMTM3NDlaFw0yNzAyMDQy
MTM3NDlaMHIxCzAJBgNVBAYTAlVTMRYwFAYDVQQIDA1NYXNzYWNodXNldHRzMRIw
EAYDVQQHDAlDYW1icmlkZ2UxHjAcBgNVBAoMFU1JVCA2MTA2IENvdXJzZSBTdGFm
ZjEXMBUGA1UEAwwOMTU3LjE4MC41Ni4xNjQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCFCiu3JXPOkADZA5G0NS/7BPqlMHmGM7I2zPVr1pJszrtBmT0Z
wRlm3n+hm6NGeHgZmxm6MslKxj/ySn+o7BIg1cGjDSX8NEinzWukCH9Gr+Z7y3R5
x4hw4JEL6A8+OINT4kI+Ltfw+ENmYu7npxHI9gu/5eTWi2eKqzOO/77WekL/H4DS
nNMi1iImI08UfOWhWdx1V0Iyj0U8C3lqUmQJGhPSJjYWY+hcf3A1acjr0nHLjyv3
lS3TX58f/iIuhn4tGsMajOPNwYGBpyB9oLck2Xd2g+utrahk6KLCQog27dIJ4xK4
x989BRsbx062IB1Wcu4zjpjO0YusGuM/12/vAgMBAAGjajBoMB0GA1UdDgQWBBRN
2XLj1Sb7LRTbHnf415BD2sIlNTAfBgNVHSMEGDAWgBRN2XLj1Sb7LRTbHnf415BD
2sIlNTAPBgNVHRMBAf8EBTADAQH/MBUGA1UdEQQOMAyHBH8AAAGHBJ20OKQwDQYJ
KoZIhvcNAQELBQADggEBAFfv05an/kReRcNXE2N3obrOAhrFgq0EXy6gMfa5Q/EC
7nIxn7sD8U/rqVl5GSmdxhBjM2ak8qfCjqsv8Xs52LGj0zMIeBw33wu7IbccGsbm
xT82yxLi/7aTj1HNMOphrS3bH9+MPdEiamKBeA47zVM6iKRIMGQpyT5bKj8L76QU
e61hFnqRk5YC9jmzH+d2f6NefbK3E1inbhCH25fdfMhqNA4jpFgff0Xbilijv64H
YySOQ4o8ObUeJ/j2uZOuf9IqxrpZMJ3X0K421A4YnqmwtntMN1kexsGCflkXmS+k
QmtQ1OBpiORL4WfSSjC8k6SxOMgSUEo3QfRUYoEWFHU=
-----END CERTIFICATE-----
"""

server_ip_port = "157.180.56.164:4443"
hidden_perf_directory = "/tmp/6106-student-jobs"

poll_interval = 1 # seconds

def log_error(e):
    response_json = json.load(e)
    error = response_json.get("error", None)
    if error: 
        print("\n" + "=" * 50)
        print("ERROR:".center(50))
        print("-" * 50)
        print(error)
        print("=" * 50 + "\n")

def process_response(response, script_args=None, job_id=None):
    result = json.loads(response["result"])["result_json"]
    if result["success"]:
        print("Job completed successfully.")
    else:
        print("Job failed.")
    print()
    print("--- Execution log:")
    print()
    print(result["execute_log"])
    
    if 'perf_data' in result and script_args:
        print()
        print("Perf data saved.")
        with open("perf.data", "wb") as f:
            f.write(base64.b64decode(result["perf_data"]))
        for idx, file in enumerate(script_args["files"]):
            if file[:2] == './': 
                file = file[2:]
            with open(file, 'rb') as f:
                file_content = f.read()
                # write this to a hidden directory
                assert job_id is not None and script_args is not None
                # if job-{job_id} doesn't exist, create it
                if not os.path.exists(os.path.join(hidden_perf_directory, f"job-{job_id}")):
                    os.makedirs(os.path.join(hidden_perf_directory, f"job-{job_id}"))
                with open(os.path.join(hidden_perf_directory, f"job-{job_id}/{file}"), "wb") as f2:
                    f2.write(file_content)
                    
    
def get_last_complete_job(username, token, ssl_ctx):
    query_params = {}
    url_query = urllib.parse.urlencode(query_params)
    url = "https://" + server_ip_port + "/api/last_complete"
    if url_query:
        url += "?" + url_query
        
    headers = {"Authorization": f"Token {username}.{token}"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, context=ssl_ctx) as f:
        response = json.load(f)
        if response["success"]:
            print("Last completed job:")
            process_response(response)
            if "perf_data" in response["result"]:
                print("Can't retrieve perf data for last job.")

def submit_job(username, token, script_args, ssl_ctx, override_pending=False, is_util=False):
    # query_params = {"username": username, "token": token}
    query_params = {}
    if override_pending:
        query_params["override_pending"] = "1"
    query_params["is_util"] = 1 if is_util else 0
    url_query = urllib.parse.urlencode(query_params)
    url = "https://" + server_ip_port + "/api/submit?" + url_query
    
    if "files" in script_args:
        for idx, file in enumerate(script_args["files"]):
            with open(file, 'rb') as f:
                file_content = f.read()
                base64_encoded = base64.b64encode(file_content).decode("utf-8")
                script_args[f"file{idx}"] = base64_encoded
    req_json = json.dumps(script_args).encode("utf-8")
    
    headers = {
        "Authorization": f"Token {username}.{token}",
        "Content-Type": "application/json"
    }
    request = urllib.request.Request(url, data=req_json, headers=headers, method="POST")
    
    try:
        response = urllib.request.urlopen(request, context=ssl_ctx)
        response_json = json.load(response)
        return response_json["job_id"]
    except urllib.error.HTTPError as e:
        if e.code == 400:
            response_json = json.load(e)
            if response_json["error"] == "pending_job":
                return None
        else:
            log_error(e)
        raise e
    
def preprocess_args(script_args):
    remaining_args = []
    files = []
    do_perf = False
    for idx, arg in enumerate(script_args):
        if idx == 0 and arg.startswith("perf"):
            assert script_args[idx + 1] == "record"
            do_perf = True

        if os.path.isfile(arg):
            remaining_args.append(f"file{len(files)}")
            files.append(arg)
        else:
            remaining_args.append(arg)
    returns = {
        "command": " ".join(remaining_args),
        "files": files,
        "perf": do_perf
    }
    return returns

def main():
    parser = argparse.ArgumentParser()
    # parser.add_argument('script_args', nargs=argparse.REMAINDER, help='Arguments for the script')
    parser.add_argument(
        "--auth",
        help="Authentication token (defaults to ./auth.json in the same directory as this script)",
        default=None
    )
    parser.add_argument(
        "--cores", 
        type=int,
        help="Number of cores to request",
        default=1
    )
    parser.add_argument("--override-pending", action="store_true", help="Allow overriding pending jobs")
    parser.add_argument("--utils", action="store_true", help="Use utility queue instead of main queue, for testing purposes instead of benchmarking performance. Timeout will be longer.")
    parser.add_argument("--bypass-last-job", action="store_true", help="Bypass checking for your last job.")
    args, script_args = parser.parse_known_args()
    if len(script_args) == 0:
        print("Please provide a script to run.")
        exit(1)
    
    # turn script_args into a dictionary 
    script_args = preprocess_args(script_args)
    script_args["cores"] = args.cores
    
    ## Check if auth token is valid
    token_path = f"{os.path.expanduser('~')}/.telerun/auth.json"
    if not os.path.isfile(token_path):
        if args.auth is None:
            print("Please provide an authentication token.")
            exit(1)
        if not os.path.isfile(args.auth):
            print("Invalid authentication token.")
            exit(1)
        if not os.path.exists(os.path.dirname(token_path)):
            os.system("mkdir -p " + os.path.dirname(token_path))   
        os.system(f"cp {args.auth} {token_path}")
        print("Authentication token copied to", token_path)
                
    ## Load auth token
    with open(token_path, "r") as f:
        auth = json.load(f)
    username = auth["username"]
    token = auth["token"]
    is_util = args.utils
    ssl_ctx = ssl.create_default_context(cadata=server_cert)

    if not args.bypass_last_job:
        last_complete_job = get_last_complete_job(username, token, ssl_ctx)

    job_id = submit_job(username, token, script_args, ssl_ctx, override_pending=args.override_pending, is_util=is_util)
    if job_id is None:
        print("You already have a pending job. Pass '--override-pending' if you want to replace it.")
        exit(1)
    print("Submitted job")

    already_claimed = False
    old_time = time.time()
    while True:
        
        if time.time() - old_time > timeout:
            print("Time limit exceeded.")
            break
        try:
            time.sleep(poll_interval)
                
            # url_query = urllib.parse.urlencode({"username": username, "token": token, "job_id": job_id})
            url_query = urllib.parse.urlencode({"job_id": job_id})
            
            headers = {"Authorization": f"Token {username}.{token}"}
            
            req = urllib.request.Request(
                "https://" + server_ip_port + "/api/status?" + url_query,
                headers=headers,
                method="GET",
            )
            with urllib.request.urlopen(req, context=ssl_ctx) as f:
                response = json.load(f)
            
            state = response["state"]
            if state == "pending":
                continue
            elif state == "claimed":
                if not already_claimed:
                    print("Compiling and running, took {:.2f} seconds to be claimed.".format(time.time() - old_time)) 
                    already_claimed = True
                continue
            elif state == "complete":
                # TODO: Don't double-nest JSON!
                process_response(response, script_args=script_args, job_id=job_id) 
                
                req = urllib.request.Request(
                    "https://" + server_ip_port + "/api/reported?" + url_query,
                    headers=headers,
                    method="POST",
                )    
                with urllib.request.urlopen(req, context=ssl_ctx) as f:
                    response = json.load(f)
                    print("Reported job completion.")
                    
                break
        except urllib.error.HTTPError as e:
            if e.code == 400:
                response_json = json.load(e)
                if response_json["error"] == "pending_job":
                    print("Server indicates a pending job error.")
                    raise e
            else: 
                log_error(e)
            raise e
        except KeyboardInterrupt as e: 
            print("Keyboard Interrupted.")
            if not already_claimed: 
                # url_query = urllib.parse.urlencode({"username": username, "token": token, "job_id": job_id})
                url_query = urllib.parse.urlencode({"job_id": job_id})
                headers = {"Authorization": f"Token {username}.{token}"}
                req = urllib.request.Request(
                    "https://" + server_ip_port + "/api/delete?" + url_query,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, context=ssl_ctx) as f:
                    response = json.load(f)
                    if response["success"]:
                        print("Job removed successfully.")
            break
        except Exception as e:
            traceback.print_exc()
            continue

if __name__ == "__main__":
    os.makedirs(hidden_perf_directory, exist_ok=True)
    main()