"""Run the existing relay with bounded checks of its own control event loop.

Camera/source health does not enter this decision. A stopped child or an
unresponsive local control loop ends this supervisor, letting Docker's existing
restart policy recover it. No Docker socket or separate host monitor is needed.
"""
import argparse
import json
import os
import signal
import subprocess
import threading
import time
try:
    from reolink_protect_events.http_deadline import get_bytes
except ModuleNotFoundError:
    from http_deadline import get_bytes


def probe(url,timeout):
    try:
        status,body=get_bytes(url,timeout=timeout,limit=65536)
        value=json.loads(body)
        return status==200 and isinstance(value,dict)and isinstance(value.get('version'),str)
    except (OSError,ValueError,TimeoutError):
        return False


def supervise(command,url,*,grace=60,interval=10,timeout=3,failures=3,
              stop=None,popen=subprocess.Popen,check=probe,clock=time.monotonic):
    stop=stop or threading.Event()
    child=popen(command,start_new_session=True)
    began=clock();failed=0;reason='child_exit'
    try:
        while not stop.wait(interval):
            code=child.poll()
            if code is not None:return code
            if clock()-began<grace:continue
            failed=0 if check(url,timeout)else failed+1
            if failed>=failures:
                reason='control_loop_unresponsive'
                print(json.dumps({'error':reason,'consecutiveFailures':failed}),flush=True)
                return 70
        reason='shutdown'
        return 0
    finally:
        if child.poll()is None:
            # The supervisor owns exactly this process group, not other apps.
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=3)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--probe',required=True)
    parser.add_argument('command',nargs=argparse.REMAINDER);args=parser.parse_args()
    command=args.command[1:]if args.command[:1]==['--']else args.command
    if not command:parser.error('child command required')
    stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    return supervise(command,args.probe,stop=stop)


if __name__=='__main__':raise SystemExit(main())
