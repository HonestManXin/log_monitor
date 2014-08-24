#-*- coding=utf-8 -*-
"""
    This app is used to monitor file.
    @Author: honestmanxin@gmail.com
"""
import os
import sys
import ConfigParser
import stat
import signal
import shelve
import time
import logging
import optparse
import re

log = logging.getLogger(__name__)
child_pid = None
#flag used by the subprocess determine if is killed by the parent process
need_shutdown = False
config = None

def run():
    """
        start monitor log_dir.
    """
    pass    

def register_subprocess_sighandler():
    """
        register the signal handler for the subprocess.
    """
    def signal_handler(dummy_signum, dummy_frame):
        """
            signal handler used to set the shut down flag.
        """
        log.info("subprocess {pid} is shutting down".format(pid=os.getpid()))
        global need_shutdown
        need_shutdown = True

    signal.signal(signal.SIGINT, signal_handler)

def register_mainprocess_sighandler():
    """
        register the signal for the main process.
    """
    def signal_handler(dummy_signum, dummy_frame):
        """
            signal handler used to shut down system.
        """
        log.info("main process is shut down")
        global need_shutdown
        need_shutdown = True
        if child_pid:
            os.kill(child_pid, signal.SIGINT)

    signal.signal(signal.SIGINT, signal_handler)


def build_logger(log_dir, name):
    """
    create the logger for the app.
    name is used to distinguish different processes.
    """
    formatter = logging.Formatter(fmt="%(levelname)s %(asctime)s %(funcName)s %(message)s", \
        datefmt="%Y-%m-%d %H:%M:%S")
    log_full_name = log_dir + os.sep + "log_" + name + ".txt"
    handler = logging.handlers.TimedRotatingFileHandler(log_full_name, when="D", encoding="encoding")
    handler.setFormatter(formatter)
    log.addHandler(handler)

def build_option_parser():
    """
    create a parser for the command-line argvs.
    """
    parser = optparse.OptionParser()
    parser.add_option("-c", "--conf", type="string", \
        dest="config_file", help="monitor config file path")
    return parser

def parse_configfile(config_file):
    """
    parse the config file.
    """
    _dummy_section = "DEFAULT"
    class _DummySection(object):
        """
            add a fake section for the config file.
        """
        def __init__(self, fd):
            self._fd = fd
            self._section = _dummy_section

        def readline(self):
            """
                let the class act as file-like object.
            """
            if self._section:
                try:
                    return "[" + self._section + "]"
                finally:
                    self._section = None
            else:
                return self._fd.readline()
    if not os.path.exists(config_file):
        sys.stderr.write("config file " + config_file + " does not exists \n")
        sys.exit(1)

    config_fd = open(config_file, 'r')
    config_with_section = _DummySection(config_fd)
    cp = ConfigParser.ConfigParser()
    cp.readfp(config_with_section)
    config = {}
    for k, v in cp.items(_dummy_section, raw=True):
        config[k] = v
    config_fd.close()
    def to_list(key, value):
        """
         convert to value to list. And the value is space delimiter.
        """
        try:
            return re.split(r"\s+", value)
        except Exception, e:
            error_string = "{key}='{value}' format is not correct\n".format(key=key, value=value)
            sys.stderr.write(error_string)
            raise e       
    def to_int(key, value):
        """
            convert value to int.
        """
        try:
            return int(value)
        except Exception, e:
            error_string = "{key}='{value}' is not a int number \n".format(key=key, value=value)
            sys.stderr.write(error_string)
            raise e
    parser = {
        "black_list": to_list,
        "white_list": to_list,
        "ext_whitelist": to_list,
        "ext_blacklist": to_list,
        "file_size": to_int,
    }
    for each_key in parser:
        if each_key in config:
            config[each_key] = parser[each_key](each_key, config[each_key])
    return config

def check_config(config):
    properties = ["monitor_dir", "log_dir", "meta_dir", \
        "black_list", "white_list", "ext_whitelist", \
        "ext_blacklist", "file_size", "rotate_time", "rotate_dir_time_format"]
    config_not_exist_error = []
    for each_pro in properties:
        if config.get(each_pro, None) is None:
            config_not_exist_error.append(each_pro + " does not appear in config file")
    if config_not_exist_error:
        sys.stderr.write("\n".join(config_not_exist_error))
        sys.exit(1)
    errors = []
    for each_file in ["monitor_dir", "log_dir", "meta_dir"]:
        if not os.path.exists(config[each_file]) or not os.path.isdir(config[each_file]):
            errors.append(each_file + " does not exists or it is not a directory")

    rotate_time = ["daily", "weekly", "monthly"]
    if not config["rotate_time"] in rotate_time:
        errors.append("rotate_time must be " + " ".join(rotate_time))
    if config["file_size"] < 2**20:
        errors.append("file_size must be greater than 1M")
    if errors:
        sys.stderr.write("\n".join(errors))
        sys.exit(1)


def fork_worker_process():
    """
        fork worker process.
    """
    pid = os.fork()
    if pid < 0:
        log.error("can not create sub process")
        sys.exit(1)
    elif pid == 0:
        run()
    else:
        log.info("fork sub process success " + str(pid))
        global child_pid
        child_pid = pid

def main():
    """
        app start function.
    """
    global config
    parser = build_option_parser()
    options = parser.parse_args()
    config = parse_configfile(options["config_file"])
    check_config(config)
    build_logger(config["log_dir"], "main")
    register_mainprocess_sighandler()
    while not need_shutdown:
        fork_worker_process()
        os.wait()

if __name__ == '__main__':
    main()


