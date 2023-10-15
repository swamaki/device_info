#!/usr/bin/env python3

import datetime
from pytz import timezone
import re
import yaml
import netdev
from netmiko import ConnectHandler
import decouple


class SSHErrors(Exception):
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


class SetConnectionParams:
    def __init__(self, device_type: str):
        self.device_type = device_type

    def set_params(self):
        """
        Set parameters for the command_file, inventory_file
        Retrieve username/password from .env file

        Return these as a dictionary and use the keys to retrieve values.

        """
        if self.device_type == "arista_eos":
            commands_file = "commands_files/arista_commands.yml"
            inventory_file = "inventory_files/arista_devices.yml"
            username = decouple.config("USER_NAME")
            password = decouple.config("PASSWORD")
        elif self.device_type == "juniper_junos":
            commands_file = "commands_files/junos_commands.yml"
            inventory_file = "inventory_files/junos_devices.yml"
            username = decouple.config("USER_NAME")
            password = decouple.config("PASSWORD")
        elif self.device_type == "linux":
            commands_file = "commands_files/linux_commands.yml"
            inventory_file = "inventory_files/linux_devices.yml"
            username = decouple.config("LINUX_ADMIN")
            password = decouple.config("PASSWORD")
        else:
            commands_file = "commands_files/cisco_commands.yml"
            inventory_file = "inventory_files/cisco_devices.yml"
            username = decouple.config("USER_NAME")
            password = decouple.config("PASSWORD")

        global_device_params = {
            "device_type": self.device_type,
            "username": username,
            "password": password,
        }
        device_params = {
            "inventory_file": inventory_file,
            "commands_file": commands_file,
            "global_device_params": global_device_params,
        }
        return device_params


class DeviceInfo:
    """
    Create the object int the form of:

    device_info = DeviceInfo(inventory_file, commands_file)

    Access methods eg:
    ip_list = device_info.get_devices_list()

    """

    def __init__(
        self, inventory_file: str, commands_file: str, global_device_params: str
    ):
        self.inventory_file = inventory_file
        self.commands_file = commands_file
        self.device_type = global_device_params["device_type"]
        self.global_device_params = global_device_params

    def get_devices_list(self):
        with open(self.inventory_file) as f:
            result = yaml.safe_load(f)
        return result["devices"]

    def get_commmands_list(self):
        with open(self.commands_file) as f:
            result = yaml.safe_load(f)
        return result["commands"]

    def extract_hostname(self, hostname_filter: str):
        device_hostname = dict()
        if (
            self.device_type == "cisco_ios"
            or self.device_type == "cisco_nxos"
            or self.device_type == "arista_eos"
        ):
            hostname_regexp = [re.compile(r"(hostname\s+)(?P<hostname>\S+)", re.M)]
        elif self.device_type == "juniper_junos":
            hostname_regexp = [re.compile(r"(host-name\s+)(?P<hostname>\S+)", re.M)]
        elif self.device_type == "linux":
            hostname_regexp = [re.compile(r"(?P<hostname>\S+)", re.M)]
        else:  # other platform versions
            hostname_regexp = [re.compile(r"(hostname\s+)(?P<hostname>\S+)", re.M)]

        for regexp in hostname_regexp:
            device_hostname.update(regexp.search(hostname_filter).groupdict())
        return device_hostname

    def save_output(self, device_hostname: str, commands_output: str):
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
        output_filename = "./outputs/%s_%.2i%.2i%i_%.2i%.2i%.2i.log" % (
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
                if (
                    self.device_type == "cisco_ios"
                    or self.device_type == "cisco_nxos"
                    or self.device_type == "arista_eos"
                ):
                    hostname_filter = await device_conn.send_command(
                        "show run | include hostname"
                    )
                elif self.device_type == "juniper_junos":
                    hostname_filter = await device_conn.send_command(
                        "show configuration | display set | match host-name"
                    )
                elif self.device_type == "linux":
                    hostname_filter = device_conn.send_command("hostname")
                else:
                    print("Cannot determine hostname for this device")

                parsed_values.update(self.extract_hostname(hostname_filter))
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
                if (
                    self.device_type == "cisco_ios"
                    or self.device_type == "cisco_nxos"
                    or self.device_type == "arista_eos"
                ):
                    hostname_filter = await device_conn.send_command(
                        "show run | include hostname"
                    )
                elif self.device_type == "juniper_junos":
                    hostname_filter = await device_conn.send_command(
                        "show configuration | display set | match host-name"
                    )
                elif self.device_type == "linux":
                    hostname_filter = device_conn.send_command("hostname")
                else:
                    print("Cannot determine hostname for this device")

                parsed_values.update(self.extract_hostname(hostname_filter))
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

    async def configure_from_file(self, ip_address):
        """
        Login and run list of commands from file on all devices on the site

        Args:
            ip_address (list): host ip address from list component

        Returns:
            hostname (dict): key is device hostname, value is dictionary containing hostname for use in saving output to file
            command output(dict): concantenated string of the outputs executed on devices

        the method used to parse the device hostname could be simpler but it's flexible enough to add other parsed variables.

        check pydoc netmiko and /send_config

        """

        device_params = self.global_device_params.copy()
        device_params["host"] = ip_address
        parsed_values = dict()

        try:
            async with netdev.create(**device_params) as device_conn:
                if (
                    self.device_type == "cisco_ios"
                    or self.device_type == "cisco_nxos"
                    or self.device_type == "arista_eos"
                ):
                    hostname_filter = await device_conn.send_command(
                        "show run | include hostname"
                    )
                elif self.device_type == "juniper_junos":
                    hostname_filter = await device_conn.send_command(
                        "show configuration | display set | match host-name"
                    )
                elif self.device_type == "linux":
                    hostname_filter = device_conn.send_command("hostname")
                else:
                    print("Cannot determine hostname for this device")

                parsed_values.update(self.extract_hostname(hostname_filter))

                print("Deploying configs on {hostname}".format(**parsed_values))

                commands_output = [
                    "Configs deployed to {hostname}".format(**parsed_values)
                ]

                config_file = (
                    "./config_files/{hostname}.conf".format(**parsed_values)
                ).lower()

                commands_output.append(
                    await device_conn.send_config_from_file(config_file)
                )
                commands_output.append("\n" + ("=" * 80) + "\n")
                all_commands_output = "\n".join(commands_output)

                result = {
                    "device_hostname": "{hostname}".format(**parsed_values),
                    "commands_output": all_commands_output,
                }
                return result

        # except netdev.exceptions.DisconnectError as e:
        except Exception as e:
            exception_msg = "Unable to login to device " + ip_address + "\n"
            exception_msg += "\n" + ("=" * 80) + "\n"
            result = {
                "device_hostname": ip_address,
                "commands_output": exception_msg,
            }
            print("Unable to login to device " + ip_address)
            print(e)
            return result
