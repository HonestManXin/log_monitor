#! /usr/bin/python
import os
import datetime
import signal
import time

PID_FILE="/home/turing/workspace/log_monitor/test_simulate/pid.txt"
LOG_DIR="/var/log/nginx"

def get_time_stamp():
    now = datetime.datetime.now()
    return now.strftime("%Y%m%d%H%M%S")

def create_file(file_name):
    full_name = os.path.join(LOG_DIR, file_name)
    with open(full_name, 'w') as dest_file:
        pass

def rotate_file():
    for file_name in os.listdir(LOG_DIR):
        if not file_name.endswith(".log") or file_name == "error.log":
            continue
        dest_file_name = file_name + "_" + get_time_stamp()
        print file_name
        print dest_file_name
        full_filename = os.path.join(LOG_DIR, file_name)
        full_destfilename = os.path.join(LOG_DIR, dest_file_name)
        os.rename(full_filename, full_destfilename)
        create_file(file_name)

def reload_log_process():
    pid = None
    with open(PID_FILE, 'r') as pid_file:
        pid = int(pid_file.read())
    os.kill(pid, signal.SIGUSR1)

def main():
    while True:
        time.sleep(60)
        rotate_file()
        reload_log_process()

if __name__ == "__main__":
    main()

