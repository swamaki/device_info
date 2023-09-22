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
import yaml
from decouple import config


# Timezone conversion for timestamping file saved filenames
est = timezone("EST")
time_now = datetime.datetime.now(est)

COMMANDS_FILE = "commands.yml"
INVENTORY_FILE = "devices.yml"


# username = input("Enter your SSH username:")
# password = getpass()

username = (config("USER_NAME"),)
password = (config("PASSWORD"),)

# # contains list of commands to be run on devices
# with open('commands_file') as f:
#     commands_list = f.read().splitlines()

# contains list of commands to be run on devices, yaml will return an element list and not  a string
with open(COMMANDS_FILE) as f:
    commands_list = yaml.full_load(f)["commands"]

# contains list of devices to login to
with open(INVENTORY_FILE) as f:
    device_list = yaml.full_load(f)

# Login to list of devices from 'devices_file'
for devices in device_list["devices"]:
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

    # Run list of commands from command_list file
    for show_command in commands_list:
        device_hostname = device_hostname.strip()
        # show_command = str(show_command)
        commands_output = net_connect.send_command(show_command, delay_factor=2)
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
        output_file.write(show_command)
        output_file.write("\n\n")
        output_file.write(commands_output)
        output_file.write("\n")
        output_file.write("-" * 50)
        output_file.write("\n")
        output_file.close


"""
1. open a file named "commands_file" for a list of devices to login into
2. open a file named "commands_file" for a list of commands to execute
3. save the output of executed commands to "filename"

confirmed working as 04/26/2020

run multiple show commands from a file  on multiple devices from a file with prompt for login

error handling

"""
