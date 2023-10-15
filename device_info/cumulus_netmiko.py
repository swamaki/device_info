#!/usr/bin/env python3

import argparse
import sys
import json

import logging
from netmiko import Netmiko
from getpass import getpass
import decouple
from device_info_lib import DeviceInfo, SetConnectionParams


def ssh_run(ip_addr, username, password, commands):
    """from the ip, login and run the commands"""

    # create the dict needed for netmiko
    device = {
        "device_type": "linux",
        "ip": ip_addr,
        "username": username,
        "password": password,
        "secret": password,  # optional, defaults to ''
        "verbose": False,  # optional, defaults to False
    }

    # This will create a file named 'test.log' in your current directory.
    # It will log all reads and writes on the SSH channel.
    logging.basicConfig(filename="test.log", level=logging.DEBUG)
    logger = logging.getLogger("netmiko")

    # initiate SSH connection
    try:
        net_connect = Netmiko(**device)

        # get the prompt if needed for later
        prompt = net_connect.find_prompt()
        print("Prompt: ", prompt)

    except Exception as err:
        print("Exception: %s" % err)

        return err

    # Now let's try to send the router a command
    output = []

    # if we sent a list of commands them run them one by one

    if isinstance(commands, list):
        for command in commands:
            output.append(net_connect.send_command(command))

    # otherwise just run the one command
    else:
        output.append(net_connect.send_command(commands))

    net_connect.disconnect()

    return output


if __name__ == "__main__":
    # username = decouple.config("LINUX_ADMIN")
    # password = decouple.config("PASSWORD")

    device_type = "linux"

    connection_params = SetConnectionParams(device_type)
    device_params = connection_params.set_params()
    global_device_params = device_params["global_device_params"]
    username = global_device_params["username"]
    password = global_device_params["password"]

    usage = (
        'usage {prog} -i <target host> -u <user> -c <"command1, command2, etc">'.format(
            prog=sys.argv[0]
        )
    )

    parser = argparse.ArgumentParser(usage=usage)
    # We add the cumulus default login credentials here
    # We are going to run "net show int json" which returns a dict of the interfaces
    parser.add_argument(
        "-i", dest="ip_addr", default="10.255.255.91", help="specify target host"
    )
    parser.add_argument(
        "-c",
        dest="commands",
        default="net show int json",
        help='specify commands separated by a command with quotes "command1,command2"',
    )
    parser.add_argument("-u", dest="user", default=username, help="specify the user")
    parser.add_argument(
        "-p", dest="passw", default=password, help="specify the password (optional)"
    )

    args = parser.parse_args()
    ip_addr = args.ip_addr

    # split the commands coming in, there might be only one
    argsin = args.commands.split(",")
    username = args.user

    # securely get the input password if not specified
    if args.passw:
        password = args.passw
    else:
        password = getpass()

    output = ssh_run(ip_addr, username, password, argsin)
    print(output)
    interfaces = json.loads(output[0])
    print(f"Interfaces: {interfaces.keys()}")
    print(f"Interface details:\n{interfaces['vlan10']}")
