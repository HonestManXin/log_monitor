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
import datetime
import logging
import optparse
import re

log = logging.getLogger(__name__)
child_pid = None
#flag used by the subprocess determine if is killed by the parent process
need_shutdown = False
global_config = None
metafile_extname_bak = ".meta.bak"
metafile_extname = ".meta"

# file_state dictionary
# 
# filename
# file_index 
# out_timestamp_dir 
# inode 
# pos

class OutHandler(object):
    def process_line(self, line):
        raise NotImplementedError

class BasicOutHandler(OutHandler):
    def __init__(self, filename, out_base_dir):
        super(BasicOutHandler, self).__init__()
        file_fullname = os.path.join(out_base_dir, filename)
        self._fd = open(file_fullname, 'a')
    
    def process_line(self, line):
        self._fd.write(line)
        self._fd.flush()

class Processor(object):
    """
     base class for log file processor.
    """

    def __init__(self, config, file_state, fd):
        """
         init the processor.
        """
        self._file_state = file_state
        self._current_file_fullpath = os.path.join(config["monitor_dir"], file_state["filename"])
        self._fd = fd
        self._config = config
        self.update_metainfo()
        self._fd.seek(file_state["pos"])
        self._outhandler = BasicOutHandler(file_state["filename"], config["out_dir"])

    def process(self):
        """
         this method process each log file.
        """
        raise NotImplementedError

    def update_metainfo(self):
        """
        update this log file's info.
        """
        meta_dir = self._config["meta_dir"]
        meta_bak_filename = os.path.join(meta_dir, self._file_state["filename"] + metafile_extname_bak)
        meta_filename = os.path.join(meta_dir, self._file_state["filename"] + metafile_extname)
        meta = shelve.open(meta_bak_filename, 'n')
        for k in self._file_state:
            meta[k] = self._file_state[k]
        meta.close()
        os.rename(meta_bak_filename, meta_filename)

class LogFileProcessor(Processor):
    """
    normal file processor.
    """
    def __init__(self, *args, **kargs):
        super(LogFileProcessor, self).__init__(*args, **kargs)

    def process(self):
        # for debug purpose
        for line in self._fd:
            print line
            self._outhandler.process_line(line)
        
        new_fd = open(self._current_file_fullpath, 'r')
        stat = os.stat(self._current_file_fullpath)
        if stat.st_ino != self._file_state["inode"]:
            log.warn("log file {filename} seems has been rotated".format(filename=self._file_state["filename"]))
            # update the fd infos
            self._fd.close()
            self._file_state["pos"] = 0
            self._file_state["inode"] = stat.st_ino
            new_fd.close() # there time window between open and os.stat function
            self._fd = open(self._current_file_fullpath, 'r')
        else:
            current_pos = self._fd.tell()
            self._file_state["pos"] = current_pos
            self._fd.close()
            self._fd = new_fd     
            self._fd.seek(current_pos, 0)
        self.update_metainfo()
        return self

    def set_read_postion_to_end(self):
        """
        set read pos from the end of the file.
        """
        self._fd.seek(0, 2)         

class RotateFileProcessor(Processor):
    """
        this processor will be used only when the processor was restart and the log file was rotated
    """
    def __init__(self, *args, **kargs):
        super(RotateFileProcessor, self).__init__(*args, **kargs)

    def process(self):
        # for debug purpose
        print "RotateFileProcessor processing"
        
        for line in self._fd:
            self._outhandler.process_line(line)
        log.info("rotated log file {inode} has been readed. change to real file".format(inode=self._file_state["inode"]))
        real_log_filepath = os.path.join(self._config["monitor_dir"], self._file_state["filename"])
        # there may have a trival bug.
        # when between open fd and get the inode ,log file happends rotate again.
        fd = open(real_log_filepath, 'r')
        inode = os.stat(real_log_filepath).st_ino
        #
        self._file_state["inode"] = inode
        self._file_state["pos"] = 0
        processor = LogFileProcessor(self._config, self._file_state, fd)
        return processor


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
    # TODO add ext_whitelist
    if filename.endswith(".log"):
        return True
    return False
 
def check_dir_update_point(config, filename_processor_map, last_check_time):
    """
    check if there are files are removed or some new logs are added.
    return last_check_time. last_check_time may be modifyed.
    """
    current_time = time.time()
    # current set it as one minute
    if current_time - last_check_time < 60:
        return last_check_time
    last_check_time = current_time
    inode_filename_map, legal_file_list = get_monitor_dir_information(config)
    #current not delete old entry
    add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list)
    return last_check_time

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
    #print inode_filename_map
    return inode_filename_map, legal_file_list

def get_inode_from_inode_filename_map(file_name, inode_filename_map):
    """
    get {file_name} inode information from inode_filename_map.
    """
    # for debug purpose
    # print file_name
    # print inode_filename_map
    for inode in inode_filename_map:
        if inode_filename_map[inode] == file_name:
            return inode
    # nerver go there
    log.error("fatal error happens, can not get {file_name} inode inode_filename_map".format(file_name=file_name))

def recover_all_meta_info(config):
    """
     read all the meta info in the meta directory.
    """
    meta_dir = config["meta_dir"]
    meta_info = {}
    for file_name in os.listdir(meta_dir):
        if file_name.endswith(metafile_extname):
            meta_fullname = os.path.join(meta_dir, file_name)
            meta_file = shelve.open(meta_fullname, 'r')
            meta = dict(meta_file)
            meta_info[meta["filename"]] = meta
            meta_file.close()
    return meta_info

def add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list, start_from_end=False):
    """
    find the if log file in legal_file_list has been add to filename_processor_map.
    """
    monitor_dir = config["monitor_dir"]
    for file_name in legal_file_list:
        if file_name not in filename_processor_map:
            current_time = datetime.datetime.now()
            log.info("{filename} has been add at {time_stamp}".format( \
                filename=file_name, time_stamp=current_time.strftime("%Y-%m-%d %H:%M:%S")))
            inode = get_inode_from_inode_filename_map(file_name, inode_filename_map)
            meta = {"filename": file_name, "pos": 0, "inode": inode}
            file_fullname = os.path.join(monitor_dir, file_name)
            fd = open(file_fullname, 'r')
            processor = LogFileProcessor(config, meta, fd)
            if start_from_end:
                processor.set_read_postion_to_end()
            filename_processor_map[file_name] = processor

def get_log_file_processor(config, meta_info, inode_filename_map, legal_file_list):
    """
    return processor for each log file.
    different type log file will be processed by different processor.
    """
    monitor_dir = config["monitor_dir"]
    filename_processor_map = {}
    for meta_name in meta_info:
        meta = meta_info[meta_name]
        inode = meta["inode"]
        if inode in inode_filename_map:
            if meta_name == inode_filename_map[inode]:
                file_fullname = os.path.join(monitor_dir, meta_name)
                fd = open(file_fullname, 'r')
                processor = LogFileProcessor(config, meta, fd)
            else:
                log.info("{filename} has been rotated".format(filename=meta_name))
                file_fullname = os.path.join(monitor_dir, inode_filename_map[inode])
                fd = open(file_fullname, 'r')
                processor = RotateFileProcessor(config, meta, fd)
        else:
            log.warn("{filename} seems been deleted".format(filename=meta_name))
            continue
        filename_processor_map[meta_name] = processor
    add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list)
    return filename_processor_map

def run(config):
    """
        start monitor log_dir.
    """
    meta_info = recover_all_meta_info(config)
    inode_filename_map, legal_file_list = get_monitor_dir_information(config)
    filename_processor_map = get_log_file_processor(config, meta_info, inode_filename_map, legal_file_list)
    last_check_time = time.time()
    while not need_shutdown:
        # consider some log file may removed situation   
        last_check_time = check_dir_update_point(config, filename_processor_map, last_check_time)
        for _, processor in filename_processor_map.iteritems():
            processor.process()
        #for debug purpose
        time.sleep(1)

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
    print "register signal handler"
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
    formatter = logging.Formatter(fmt="%(levelname)s %(asctime)s %(lineno)d %(funcName)s %(message)s", \
        datefmt="%Y-%m-%d %H:%M:%S")
    log_full_name = log_dir + os.sep + "log_" + name + ".txt"
    from logging import handlers
    #handler = handlers.TimedRotatingFileHandler(log_full_name, when="D", encoding="utf-8")
    handler = logging.StreamHandler()
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
    from log_util import to_list, to_int, to_end_with_reg_list
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
    properties = ["monitor_dir", "log_dir", "meta_dir", "out_dir", \
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
    for each_pro in ["monitor_dir", "log_dir", "meta_dir", "out_dir"]:
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
        run(global_config)
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
    (options, _) = parser.parse_args()
    global_config = parse_configfile(options.config_file)
    check_config(global_config)
    build_logger(global_config["log_dir"], "main")
    register_mainprocess_sighandler()

    fork_worker_process()
    os.wait()
    # while not need_shutdown:
    #     fork_worker_process()
    #     os.wait()

if __name__ == '__main__':
    main()

