#!/usr/bin/env python3

import time
import datetime
from getpass import getpass
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import AuthenticationException
from paramiko.ssh_exception import SSHException
from pytz import timezone
import re

# Timezone conversion for timestamping file saved filenames
est = timezone("EST")
time_now = datetime.datetime.now(est)

username = input("Enter your SSH username:")
password = getpass()

# contains list of commands to be run on IOS XE routers and switches
with open("commands_file_iosxe") as f:
    commands_list_iosxe = f.read().splitlines()

# contains list of commands to be run on NX-OS routers and switches
with open("commands_file_nexus") as f:
    commands_list_nexus = f.read().splitlines()

# contains list of commands to be run on switches
with open("commands_file_switch") as f:
    commands_list_switch = f.read().splitlines()

# contains list of commands to be run on routers
with open("commands_file_router") as f:
    commands_list_router = f.read().splitlines()

# contains list of devices to login to
with open("devices_file") as f:
    device_list = f.read().splitlines()

# Login to list of devices from 'devices_file'
for devices in device_list:
    print("\n")
    print("-" * 50)
    print("Connecting to device " + devices)
    ip_address_of_device = devices
    ios_device = {
        "device_type": "cisco_ios",
        "ip": ip_address_of_device,
        "username": username,
        "password": password,
    }
    try:
        net_connect = ConnectHandler(**ios_device)
    except (AuthenticationException):
        print("Authenticaiton Failure: " + ip_address_of_device)
        continue
    except (NetMikoTimeoutException):
        print("Timeout to device: " + ip_address_of_device)
        continue
    except (EOFError):
        print("End of file while attempting device " + ip_address_of_device)
        continue
    except (SSHException):
        print("SSH issue. Are you sure SSH is enabled on " + ip_address_of_device + "?")
        continue
    except Exception as unknown_error:
        print("Some other error " + unknown_error)
        continue

    # Extract the device hostname from running configuration
    net_connect.send_command("term len 0")
    running_config = net_connect.send_command("show run")
    device_hostname = re.search(
        r"^hostname (.*)\s*$", running_config, flags=re.M
    ).group(1)
    print("Connected to: " + device_hostname)
    print("Running all the relevant commands on " + device_hostname + ", please wait.")

    # Types of devices
    list_versions = [
        "IOS XE",
        "NX-OS",
        "C2960X-UNIVERSALK9-M",
        "vios_l2-ADVENTERPRISEK9-M",
        "VIOS-ADVENTERPRISEK9-M",
    ]
    # Check software versions
    for software_ver in list_versions:
        print("Checking for " + software_ver)
        output_version = net_connect.send_command("show version")
        int_version = 0  # Reset integer value
        int_version = output_version.find(software_ver)  # Check software version
        if int_version > 0:
            print("Software version found " + software_ver)
            break
        else:
            print("Did not find " + software_ver)

    # Run 'IOS-XE' relevant commands (routers/switches)
    if software_ver == "IOS XE":
        print("Running " + software_ver + " commands")
        for show_command_iosxe in commands_list_iosxe:
            device_hostname = device_hostname.strip()
            show_command_iosxe = str(show_command_iosxe)
            commands_output_iosxe = net_connect.send_command(
                show_command_iosxe, delay_factor=2
            )
            # time.sleep(5)
            output_filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i" % (
                device_hostname,
                time_now.year,
                time_now.month,
                time_now.day,
                time_now.hour,
                time_now.minute,
                time_now.second,
            )
            output_file = open(output_filename, "a")
            output_file.write(show_command_iosxe)
            output_file.write("\n\n")
            output_file.write(commands_output_iosxe)
            output_file.write("\n")
            output_file.write("-" * 50)
            output_file.write("\n")
            output_file.close

    # Run 'NX-OS' relevant commands on (nexus)
    elif software_ver == "NX-OS":
        print("Running " + software_ver + " commands")
        for show_command_nexus in commands_list_nexus:
            device_hostname = device_hostname.strip()
            show_command_nexus = str(show_command_nexus)
            commands_output_nexus = net_connect.send_command(
                show_command_nexus, delay_factor=2
            )
            # time.sleep(5)
            output_filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i.txt" % (
                device_hostname,
                time_now.year,
                time_now.month,
                time_now.day,
                time_now.hour,
                time_now.minute,
                time_now.second,
            )
            output_file = open(output_filename, "a")
            output_file.write(show_command_nexus)
            output_file.write("\n\n")
            output_file.write(commands_output_nexus)
            output_file.write("\n")
            output_file.write("-" * 50)
            output_file.write("\n")
            output_file.close

    # Run 'vios_l2-ADVENTERPRISEK9-M' relevant commands (switches)
    elif software_ver == "vios_l2-ADVENTERPRISEK9-M":
        print("Running " + software_ver + " commands")
        for show_command_switch in commands_list_switch:
            device_hostname = device_hostname.strip()
            show_command_switch = str(show_command_switch)
            commands_output_switch = net_connect.send_command(
                show_command_switch, delay_factor=2
            )
            # time.sleep(5)
            output_filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i" % (
                device_hostname,
                time_now.year,
                time_now.month,
                time_now.day,
                time_now.hour,
                time_now.minute,
                time_now.second,
            )
            output_file = open(output_filename, "a")
            output_file.write(show_command_switch)
            output_file.write("\n\n")
            output_file.write(commands_output_switch)
            output_file.write("\n")
            output_file.write("-" * 50)
            output_file.write("\n")
            output_file.close

    # Run 'VIOS-ADVENTERPRISEK9-M' relevant commands (routers)
    elif software_ver == "VIOS-ADVENTERPRISEK9-M":
        print("Running " + software_ver + " commands")
        # commands_output = net_connect.send_config_set(commands_list_router)
        for show_command_router in commands_list_router:
            device_hostname = device_hostname.strip()
            show_command_router = str(show_command_router)
            commands_output_router = net_connect.send_command(
                show_command_router, delay_factor=2
            )
            # time.sleep(5)
            output_filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i" % (
                device_hostname,
                time_now.year,
                time_now.month,
                time_now.day,
                time_now.hour,
                time_now.minute,
                time_now.second,
            )
            output_file = open(output_filename, "a")
            output_file.write(show_command_router)
            output_file.write("\n\n")
            output_file.write(commands_output_router)
            output_file.write("\n")
            output_file.write("-" * 50)
            output_file.write("\n")
            output_file.close

"""
confirmed working

run multiple show commands from a file  on multiple devices from a file with prompt for login

error handling  + software version check

"""

