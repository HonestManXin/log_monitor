#-*- coding=utf-8 -*-
"""
    test cases used to test log_monitor.
"""
from log_monitor import parse_configfile
from log_monitor import check_config

def test_parse_configfile():
    config = parse_configfile('monitor.conf')
    print config

def test_check_config():
    config = parse_configfile('monitor.conf')
    check_config(config)

if __name__ == '__main__':
    test_parse_configfile()
    test_check_config()



