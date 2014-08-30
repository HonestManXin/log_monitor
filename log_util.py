#-*- coding=utf-8 -*-
"""
    This module is used to provid some util function for log_monitor.
    @Author: honestmanxin@gmail.com
"""
import re
import sys

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
