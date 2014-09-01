#-*- coding=utf-8 -*-
import os
import time
import signal
import datetime

log_dir = "/var/log/nginx"
#log_name_list = ["access.log", "test.log"]
log_name_list = ["access.log"]
switch_file = False

def handler(signum, frame):
    print "get signal"
    global switch_file
    switch_file = True


def get_open_file_list():
    file_list = []
    for file_name in log_name_list:
        full_name = os.path.join(log_dir, file_name)
        file_list.append(open(full_name, 'a+'))
    return file_list


def close_all_file(file_list):
    for open_file in file_list:
        open_file.close()

def switch_file_if_necessary(open_file_list):
    global switch_file
    if not switch_file:
        return open_file_list
    else:
        close_all_file(open_file_list)
        switch_file = False
        return get_open_file_list()

line_count = 0
def get_log_line():
    current_time = datetime.datetime.now()
    domain_name = "www.google.com"
    time_stamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
    return "{domain_name} {time_stamp} {line_count}\n".format(domain_name=domain_name, time_stamp=time_stamp, line_count=line_count)

def write_log():
    open_file_list = get_open_file_list()
    while True:
        global line_count
        line_count += 1
        open_file_list = switch_file_if_necessary(open_file_list)
        for open_file in open_file_list:
            line = get_log_line()
            open_file.write(line)
            open_file.flush()
        time.sleep(1)

def write_pid():
    pid = os.getpid()
    with open("pid.txt", "w") as pid_file:
        pid_file.write(str(pid))

def main():
    signal.signal(signal.SIGUSR1, handler)
    write_pid()
    write_log()

if __name__ == "__main__":
    main()
