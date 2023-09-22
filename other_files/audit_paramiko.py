#!/usr/bin/env python3

import sys
import os
import cmd
import time
import datetime
import paramiko
from pytz import timezone
from getpass import getpass

time_now = datetime.datetime.now()

username = input("Enter your SSH username:")
password = getpass()

with open("devices_file") as f:
    device_list = f.read().splitlines()

for ip_address in device_list:
    ip_address = ip_address.strip()
    filename_prefix = "/config_backup" + ip_address
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        hostname=ip_address, username=username, password=password, look_for_keys=False
    )
    print("Successful connection" + str(ip_address))
    net_connect = ssh_client.invoke_shell()
    time.sleep(2)
    net_connect.send("term len 0\n")
    time.sleep(1)
    print("Getting running-config " + str(ip_address))
    net_connect.send("sh run\n")
    time.sleep(10)
    output = net_connect.recv(999999)
    filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i.txt" % (
        ip_address,
        time_now.year,
        time_now.month,
        time_now.day,
        time_now.hour,
        time_now.minute,
        time_now.second,
    )
    output_file = open(filename, "a")
    output_file.write(output.decode("utf-8"))
    output_file.close()
    ssh_client.close()

