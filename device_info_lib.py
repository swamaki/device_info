#!/usr/bin/env python3

import datetime
from pytz import timezone
import re
import yaml
import netdev
from netmiko import ConnectHandler

class DeviceInfo:
    """
    Create the object int the form of:

    device_info = DeviceInfo(inventory_file, commands_file)

    Access methods eg:
    ip_list = device_info.get_devices_list()

    """

    def __init__(self, inventory_file, commands_file, platform_ver, global_device_params):
        self.inventory_file = inventory_file
        self.commands_file = commands_file
        self.platform_ver = platform_ver
        self.global_device_params = global_device_params

    def get_devices_list(self):
        with open(self.inventory_file) as f:
            result = yaml.safe_load(f)
        return result["devices"]

    def get_commmands_list(self):
        with open(self.commands_file) as f:
            result = yaml.safe_load(f)
        return result["commands"]

    def extract_hostname(self, sh_ver):
        device_hostname = dict()
        for regexp in self.software_ver_check(sh_ver):
            device_hostname.update(regexp.search(sh_ver).groupdict())
        return device_hostname

    def software_ver_check(self, sh_ver):
        # Types of devices
        version_list = [
            "IOS XE",
            "NX-OS",
            "Cisco IOSv",
            "C2960X-UNIVERSALK9-M",
            "vios_l2-ADVENTERPRISEK9-M",
            "VIOS-ADVENTERPRISEK9-M",
            "Junos",
            "Arista",
            "Cumulus",
        ]
        # Check software versions
        for version in version_list:
            int_version = 0  # Reset integer value
            int_version = sh_ver.find(version)  # Check software version
            if int_version > 0:  # software version found, break out of loop.
                break

        if version == "NX-OS":
            parsed_hostname = [
                re.compile(r"(^\s+)+(Device name:)\s(?P<hostname>\S+)", re.M)
            ]
        elif version == "Cisco IOSv":
            parsed_hostname = [re.compile(r"(?P<hostname>^\S+)\s+uptime", re.M)]
        elif version == "Junos":
            parsed_hostname = [re.compile(r"(^Hostname:\s+)(?P<hostname>\S+)", re.M)]
        elif version == "Arista":
            parsed_hostname = [re.compile(r"(^Hostname:\s+)(?P<hostname>\S+)", re.M)]
        elif version == "Cumulus":
            parsed_hostname = [re.compile(r"(^hostname\s+)(?P<hostname>\S+)", re.M)]
        else:  # other platform versions
            parsed_hostname = [re.compile(r"(^Hostname:\s+)(?P<hostname>\S+)", re.M)] #arista vEOS
            # print("Cannot determine the platform version for this device")

        return parsed_hostname

    def save_output(self, device_hostname, commands_output):
        """
        writes outputs to a file.

        Args:
            device_hostname (string): parsed hostname of device on which commands were executed
            command output(dict): concantenated string of the outputs executed on devices

        Returns:
            Filename is timestamped with date etc

        """

        est = timezone("EST")
        time_now = datetime.datetime.now(est)
        output_filename = "%s_%.2i%.2i%i_%.2i%.2i%.2i.log" % (
            device_hostname,
            time_now.year,
            time_now.month,
            time_now.day,
            time_now.hour,
            time_now.minute,
            time_now.second,
        )
        # output_filename = "%s.txt" % (device_hostname) #filenames without timestamps
        output_file = open(output_filename, "a")
        output_file.write(commands_output)
        output_file.close

    async def commands_output(self, ip_address):
        """
        Login and run list of commands from file on all devices on the site

        Args:
            ip_address (list): host ip address from list component

        Returns:
            hostname (dict): key is device hostname, value is dictionary containing hostname for use in saving output to file
            command output(dict): concantenated string of the outputs executed on devices

        the method used to parse the device hostname could be simpler but it's flexible enough to add other parsed variables.

        """
        
        device_params = self.global_device_params.copy()
        device_params["host"] = ip_address
        parsed_values = dict()

        try:
            async with netdev.create(**device_params) as device_conn:
                if self.platform_ver == "cisco_ios": 
                    show_version_output = await device_conn.send_command("show version")
                elif self.platform_ver == "arista_eos": 
                    show_ver_commands = ["show hostname", "show version"]
                    show_version_output = ""
                    for command in show_ver_commands: 
                        show_version_output+= await device_conn.send_command(command)
                    """ TODO: Need to determine hostname extraction for Arista vEOS with a single 
                        command or send multiple commands at once. 
                    """
                    
                    # show_version_output = await device_conn.send_command("show hostname")
                    # show_version_output+= await device_conn.send_command("show ver")
                    # print(show_version_output)
                elif self.platform_ver == "juniper_junos": 
                    show_version_output = await device_conn.send_command("show version")
                elif self.platform_ver == "linux": 
                    show_version_output = device_conn.send_command("nv show system")
                else: 
                    print("Cannot determine hostname for this device")

                parsed_values.update(self.extract_hostname(show_version_output))
                # print(show_version_output)
                print("Running commands on {hostname}".format(**parsed_values))

                commands_list = self.get_commmands_list()
                commands_output = [
                    "Ping/Traceroute commands of {hostname}".format(**parsed_values)
                ]
                for show_command in commands_list:
                    commands_output.append(
                        "\n" + ("-" * 60) + "\n\n" + show_command + "\n\n"
                    )
                    commands_output.append(await device_conn.send_command(show_command))
                commands_output.append("\n" + ("=" * 80) + "\n")
                all_commands_output = "\n".join(commands_output)

                result = {
                    "device_hostname": "{hostname}".format(**parsed_values),
                    "commands_output": all_commands_output,
                }
                return result
                # yield result

        # except netdev.exceptions.DisconnectError as e:
        except Exception as e:
            exception_msg = "Unable to login to device " + ip_address + "\n"
            exception_msg += str(e)
            exception_msg += "\n" + ("=" * 80) + "\n"
            result = {
                "device_hostname": ip_address,
                "commands_output": exception_msg,
            }
            print("Unable to login to device " + ip_address)
            print(e)
            return result
        
    async def commands_output_netmiko(self, ip_address):
        """
        Login and run list of commands from file on all devices on the site

        Args:
            ip_address (list): host ip address from list component

        Returns:
            hostname (dict): key is device hostname, value is dictionary containing hostname for use in saving output to file
            command output(dict): concantenated string of the outputs executed on devices

        the method used to parse the device hostname could be simpler but it's flexible enough to add other parsed variables.

        """
        
        device_params = self.global_device_params.copy()
        device_params["host"] = ip_address
        parsed_values = dict()

        try:
            with ConnectHandler(**device_params) as device_conn:
                if self.platform_ver == "cisco_ios": 
                    show_version_output = device_conn.send_command("show version")
                elif self.platform_ver == "arista_eos": 
                    show_ver_commands = ["show hostname", "show version"]
                    show_version_output = ""
                    for command in show_ver_commands: 
                        show_version_output+= device_conn.send_command(command)
                    """ TODO: Need to determine hostname extraction for Arista vEOS with a single 
                        command or send multiple commands at once. 
                    """
                    
                    # show_version_output = await device_conn.send_command("show hostname")
                    # show_version_output+= await device_conn.send_command("show ver")
                    # print(show_version_output)
                elif self.platform_ver == "juniper_junos": 
                    show_version_output = device_conn.send_command("show version")
                elif self.platform_ver == "linux": 
                    show_version_output = device_conn.send_command("nv show system")
                else: 
                    print("Cannot determine hostname for this device")

                parsed_values.update(self.extract_hostname(show_version_output))
                # print(show_version_output)
                print("Running commands on {hostname}".format(**parsed_values))

                commands_list = self.get_commmands_list()
                commands_output = [
                    "Ping/Traceroute commands of {hostname}".format(**parsed_values)
                ]
                for show_command in commands_list:
                    commands_output.append(
                        "\n" + ("-" * 60) + "\n\n" + show_command + "\n\n"
                    )
                    commands_output.append(device_conn.send_command(show_command))
                commands_output.append("\n" + ("=" * 80) + "\n")
                all_commands_output = "\n".join(commands_output)

                result = {
                    "device_hostname": "{hostname}".format(**parsed_values),
                    "commands_output": all_commands_output,
                }
                return result
                # yield result

        # except netdev.exceptions.DisconnectError as e:
        except Exception as e:
            exception_msg = "Unable to login to device " + ip_address + "\n"
            exception_msg += str(e)
            exception_msg += "\n" + ("=" * 80) + "\n"
            result = {
                "device_hostname": ip_address,
                "commands_output": exception_msg,
            }
            print("Unable to login to device " + ip_address)
            print(e)
            return result


