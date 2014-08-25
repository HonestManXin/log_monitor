#-*- coding=utf-8 -*-
"""
    This app is used to monitor file.
    @Author: honestmanxin@gmail.com
"""
import os
import sys
import ConfigParser
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
global_config = None

class Processor(object):
    def __init__(self, config, filename, fd, inode, out_dir, file_index=0, pos=0):
        self._filename = filename
        self._current_file_fullpath = os.path.join(config["monitor_dir"], filename)
        self._fd = fd
        self._inode = inode
        self._pos = pos
        self._out_dir = out_dir
        self._outname = filename + "." + str(file_index)
        self._file_index = file_index
        self._config = config
        self._get_current_outfile_info()

    def _get_current_outfile_info(self):
        out_full_path = os.path.join(self._out_dir, self._outname)
        if os.path.exists(out_full_path):
            stat = os.stat(out_full_path)
            self._out_size = stat.st_size
        else:
            self._out_size = 0
        self._out_fd = open(out_full_path, 'a+')

    def _write_line(line):
        """
            write one line log to the outname.
        """
        self._out_fd.write(line)
        self._out_size += len(line)
        self._pos = self._fd.tell()
        if self._out_size >= self._config["zip_size"]:
            self._file_index += 1
            self.update_metainfo()
            #start zip file
            pass
        else:
            self.update_metainfo()

    def process(self):
        raise NotImplementedError

    def update_outdir(self):
        raise NotImplementedError

    def update_metainfo(self):
        pass

class LogFileProcessor(Processor):
    def __init__(self, *args, **kargs):
        super(LogFileProcessor, self).__init__(*args, **kargs)

    def process(self):
        for line in self._fd:
            self._write_line(line)

        stat = os.stat(self._current_file_fullpath)
        if stat.st_ino == self._inode:
            return self
        else:
            log.warn("log file {filename} seems has been rotated".format(filename=self._filename))
            #update the fd infos
            return self         

class RotateFileProcessor(Processor):
    def __init__(self, *args, **kargs):
        super(RotateFileProcessor, self).__init__(*args, **kargs)

    def process(self):
        for line in self._fd:
            self._write_line(line)
        log.info("rotated log file {inode} has been readed. change to real file".format(inode=self._inode))
        real_log_filepath = os.path.join(self._config["monitor_dir"], self._filename)
        # there may have a trival bug.
        # when between open fd and get the inode ,log file happends rotate again.
        fd = open(real_log_filepath, 'r')
        inode = os.stat(real_log_filepath).st_ino
        #
        processor = LogFileProcessor(self._config, self._filename, fd, inode, self._out_dir, \
            self._file_index)



def is_legal_log_file(config, filename):
    """
    if the file is a legal log file accoding to black_list, 
    white_list and ext_blacklist
    """
    if filename in config["white_list"]:
        return True
    if filename in config["black_list"]:
        return False
    for reg_exp in config["ext_blacklist"]:
        if reg_exp.match(filename):
            return False
    return True
 
def check_point(config):
    """
    check if there are files are removed.
    """
    pass

def change_output_dir(config):
    """
    """
    pass   

def get_monitor_dir_information(config):
    """
    return file inode and file map and 
        all the legal log file.
    """
    monitor_dir = config["monitor_dir"]
    inode_filename_map = {}
    legal_file_list = []
    for filename in os.listdir(monitor_dir):
        file_full_path = os.path.join(monitor_dir, filename)
        stat = os.stat(file_full_path)
        inode_filename_map[stat.st_ino] = filename
        if is_legal_log_file(config, filename):
            legal_file_list.append(filename)

    return inode_filename_map, legal_file_list


def recover_all_meta_info(config):
    pass

def update_infomation(filename, info_dict):
    pass

def run():
    """
        start monitor log_dir.
    """
    meta_info = recover_all_meta_info(config)
    inode_filename_map, legal_file_list = get_monitor_dir_information(config)
    while not need_shutdown:
        # consider some log file may removed situation   

        #

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
    config_info = {}
    for k, v in cp.items(_dummy_section, raw=True):
        config_info[k] = v
    config_fd.close()
    def to_list(key, value):
        """
         convert to value to list. And the value is space delimiter.
        """
        try:
            values = re.split(r"\s+", value)
            values = [i for i in values if i != '']
            return values
        except Exception, e:
            error_string = "{key}='{value}' format is not correct\n".format(key=key, value=value)
            sys.stderr.write(error_string)
            raise e

    def to_end_with_reg_list(key, value):
        """
        convert each value to reg list.
        """
        values = to_list(key, value)
        reg_list = []
        for item in values:
            reg_list.append(re.compile(item + r"$"))
        return reg_list

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
        "ext_blacklist": to_end_with_reg_list,
        "zip_size": to_int,
    }
    for each_key in parser:
        if each_key in config_info:
            config_info[each_key] = parser[each_key](each_key, config_info[each_key])
    return config_info

def check_config(config):
    """
        check config arguments.
    """
    properties = ["monitor_dir", "log_dir", "meta_dir", \
        "black_list", "white_list", "ext_blacklist", \
        "zip_size", "rotate_dir_time", "rotate_dir_time_format"]
    config_not_exist_error = []
    for each_pro in properties:
        if config.get(each_pro, None) is None:
            config_not_exist_error.append(each_pro + " does not appear in config file")
    if config_not_exist_error:
        sys.stderr.write("\n".join(config_not_exist_error))
        sys.exit(1)
    errors = []
    for each_pro in ["monitor_dir", "log_dir", "meta_dir"]:
        if not os.path.exists(config[each_pro]) or not os.path.isdir(config[each_pro]):
            errors.append(each_pro + " does not exists or it is not a directory")

    rotate_dir_time = ["daily", "weekly", "monthly"]
    if not config["rotate_dir_time"] in rotate_dir_time:
        errors.append("rotate_dir_time must be " + " ".join(rotate_dir_time))
    if config["zip_size"] < 2**20:
        errors.append("zip_size must be greater than 1M")
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
    global global_config
    parser = build_option_parser()
    options = parser.parse_args()
    global_config = parse_configfile(options["config_file"])
    check_config(global_config)
    build_logger(global_config["log_dir"], "main")
    register_mainprocess_sighandler()
    while not need_shutdown:
        fork_worker_process()
        os.wait()

if __name__ == '__main__':
    main()

