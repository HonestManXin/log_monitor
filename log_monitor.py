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
# filename file_index 
# out_timestamp_dir inode pos

class Processor(object):
    """
     base class for log file processor.
    """
    @staticmethod
    def generate_outfilename(filename, index):
        """
        generate out file name according to the filename and the file index.
        """
        return filename + "." + str(index)

    @staticmethod
    def generate_outfile_fullpath(out_base_dir, timestamp_dir, filename):
        """
         generate out file full path.
        """
        dir_fullpath = os.path.join(out_base_dir, timestamp_dir)
        file_fullpath = os.path.join(dir_fullpath, filename)
        return file_fullpath

    def __init__(self, config, file_state, fd, out_timestamp_dir):
        """
         init the processor.
        """
        need_update = False
        if file_state["out_timestamp_dir"] != out_timestamp_dir:
            file_state["out_timestamp_dir"] = out_timestamp_dir
            file_state["file_index"] = 0
            need_update = True
        self._file_state = file_state
        self._current_file_fullpath = os.path.join(config["monitor_dir"], file_state["filename"])
        self._fd = fd
        self._out_timestamp_dir = out_timestamp_dir
        self._out_size = 0
        self._out_fd = None
        self._outname = Processor.generate_outfilename(file_state["filename"], file_state["file_index"])
        self._config = config
        self._output_fullpath = None
        self._get_current_outfile_info()
        if need_update:
            self.update_metainfo()

    def _get_current_outfile_info(self):
        """
            get current out file infomation.
            and open the out file.
        """
        self._output_fullpath = Processor.generate_outfile_fullpath(self._config["out_dir"], \
            self._out_timestamp_dir, self._outname)
        if os.path.exists(self._output_fullpath):
            stat = os.stat(self._output_fullpath)
            self._out_size = stat.st_size
        else:
            self._out_size = 0
        self._out_fd = open(self._output_fullpath, 'a')

    def _update_file_index(self):
        """
        according to time_stamp_dir to decided increment the file_index.
        """
        right_first_slash = self._output_fullpath.rfind("/")
        right_second_slash = self._output_fullpath.rfind("/", 0, right_first_slash)
        old_timestamp_dir = self._output_fullpath[right_second_slash+1:right_first_slash]
        if old_timestamp_dir != self._out_timestamp_dir:
            # This happends when the output dir need rotate
            log.warn("output dir seems changed from {old_dir} to {new_dir}".format(\
                old_dir=old_timestamp_dir, new_dir=self._out_timestamp_dir))
        else:
            self._file_state["file_index"] += 1

    def _process_line(self, line):
        """
            write one line log to the outname.
        """
        self._out_fd.write(line)
        self._out_size += len(line)
        self._file_state["pos"] = self._fd.tell()
        if self._out_size >= self._config["zip_size"]:
            self._out_fd.close()
            #self._file_state["file_index"] += 1
            self._update_file_index()
            self.update_metainfo()
            #start zip file
            shell_command = "gzip {filename} &".format(filename=self._output_fullpath)
            os.system(shell_command)
            #open new outname
            self._outname = Processor.generate_outfilename(self._file_state["filename"], self._file_state["file_index"])
            self._output_fullpath = Processor.generate_outfile_fullpath(self._config["out_dir"], \
                self._out_timestamp_dir, self._outname)
            self._out_fd = open(self._output_fullpath, 'a+')
            self._out_size = 0
        else:
            self.update_metainfo()

    def process(self):
        """
         this method process each log file.
        """
        raise NotImplementedError

    def update_outdir(self, timestamp_dir):
        """
            update out dir.
            but it doesn't change it right now.
        """
        assert timestamp_dir != None
        log.info("{filename} outdir changed from {old_dir} to {new_dir}".format(\
            filename=self._file_state["filename"], old_dir=self._out_timestamp_dir, new_dir=timestamp_dir))
        if timestamp_dir:
            self._out_timestamp_dir = timestamp_dir
            self._file_state["out_timestamp_dir"] = timestamp_dir
            self._file_state["file_index"] = 0
            self.update_metainfo()

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
        for line in self._fd:
            self._process_line(line)

        stat = os.stat(self._current_file_fullpath)
        if stat.st_ino == self._file_state["inode"]:
            return self
        else:
            log.warn("log file {filename} seems has been rotated".format(filename=self._file_state["filename"]))
            #update the fd infos
            return self         

class RotateFileProcessor(Processor):
    """
        this processor will be used only when the processor was restart and the log file was rotated
    """
    def __init__(self, *args, **kargs):
        super(RotateFileProcessor, self).__init__(*args, **kargs)

    def process(self):
        for line in self._fd:
            self._process_line(line)
        log.info("rotated log file {inode} has been readed. change to real file".format(inode=self._file_state["inode"]))
        real_log_filepath = os.path.join(self._config["monitor_dir"], self._file_state["filename"])
        # there may have a trival bug.
        # when between open fd and get the inode ,log file happends rotate again.
        fd = open(real_log_filepath, 'r')
        inode = os.stat(real_log_filepath).st_ino
        #
        self._file_state["inode"] = inode
        self._file_state["pos"] = 0
        processor = LogFileProcessor(self._config, self._file_state, fd, self._out_timestamp_dir)
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
    return True
 
def check_dir_update_point(config, filename_processor_map, out_timestamp_dir, last_check_time):
    """
    check if there are files are removed or some new logs are added.
    """
    current_time = time.time()
    # current set it as one minute
    if current_time - last_check_time < 60:
        return last_check_time
    last_check_time = current_time
    inode_filename_map, legal_file_list = get_monitor_dir_information(config)
    #current not delete old entry
    add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list, out_timestamp_dir)
    return last_check_time

def check_need_rotate_outdir(config, filename_processor_map, last_out_timestamp_dir):
    """
    check if it's time to rotate the dir.
    if so, change it.
    """
    now = datetime.datetime.now()
    if now.minute % 5 == 0:
        current_out_timestmp_dir = compute_current_out_timestmp_dir(config, now)
        if current_out_timestmp_dir != last_out_timestamp_dir:
            # update
            for _, processor in filename_processor_map.iteritems():
                processor.update_outdir(current_out_timestmp_dir)
        last_out_timestamp_dir = current_out_timestmp_dir
    return last_out_timestamp_dir

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
        inode_filename_map[filename] = stat.st_ino
        if is_legal_log_file(config, filename):
            legal_file_list.append(filename)
    #print inode_filename_map
    return inode_filename_map, legal_file_list

def get_inode_from_inode_filename_map(file_name, inode_filename_map):
    """
    get {file_name} inode information from inode_filename_map.
    """
    print file_name
    print inode_filename_map
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
            with shelve.open(meta_fullname, 'r') as meta_file:
                meta_info[file_name] = dict(meta_file)
    return meta_info

def add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list, out_timestamp_dir):
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
            meta = {"filename": file_name, "pos": 0, "file_index":0, \
                "out_timestamp_dir": out_timestamp_dir, "inode": inode}
            file_fullname = os.path.join(monitor_dir, file_name)
            fd = open(file_fullname, 'r')
            processor = LogFileProcessor(config, meta, fd, out_timestamp_dir)
            filename_processor_map[file_name] = processor

def get_log_file_processor(config, meta_info, inode_filename_map, legal_file_list, out_timestamp_dir):
    """
    return processor for each log file.
    different type log file will be processed by different processor.
    """
    filename_processor_map = {}
    for meta_name in meta_info:
        meta = meta_info[meta_name]
        inode = meta["inode"]
        if inode in inode_filename_map:
            if meta_name == inode_filename_map[inode]:
                fd = open(meta_name, 'r')
                processor = LogFileProcessor(config, meta, fd, out_timestamp_dir)
            else:
                log.info("{filename} has been rotated".format(filename=meta_name))
                fd = open(inode_filename_map[inode], 'r')
                processor = RotateFileProcessor(config, meta, fd, out_timestamp_dir)
        else:
            log.warn("{filename} seems been deleted".format(filename=meta_name))
            continue
        filename_processor_map[meta_name] = processor
    add_new_logfile_processor(config, filename_processor_map, inode_filename_map, legal_file_list, out_timestamp_dir)
    return filename_processor_map

def compute_current_out_timestmp_dir(config, time_stamp=None):
    """
    time_stamp is instance of datetime.
    return dir name represented as time time_stamp format.
    """
    if time_stamp:
        out_timestamp_dir_name = time_stamp.strftime(config["rotate_dir_time_format"])
    else:
        time_stamp = datetime.datetime.now()
        minute = time_stamp.minute
        if minute % 5 == 0:
            out_timestamp_dir_name = time_stamp.strftime(config["rotate_dir_time_format"])
        else:
            proper_time = time_stamp - datetime.timedelta(seconds=60*(minute%5))
            out_timestamp_dir_name = proper_time.strftime(config["rotate_dir_time_format"])
    out_dir = config["out_dir"]
    full_path = os.path.join(out_dir, out_timestamp_dir_name)
    if not os.path.exists(full_path):
        os.mkdir(full_path)
    return out_timestamp_dir_name

def run(config):
    """
        start monitor log_dir.
    """
    meta_info = recover_all_meta_info(config)
    inode_filename_map, legal_file_list = get_monitor_dir_information(config)
    last_out_timestamp_dir = compute_current_out_timestmp_dir(config)
    filename_processor_map = get_log_file_processor(config, meta_info, inode_filename_map, legal_file_list, last_out_timestamp_dir)
    last_check_time = time.time()
    while not need_shutdown:
        # consider some log file may removed situation   
        last_check_time = check_dir_update_point(config, filename_processor_map, last_out_timestamp_dir, last_check_time)
        last_out_timestamp_dir = check_need_rotate_outdir(config, filename_processor_map, last_out_timestamp_dir)
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

