#!/usr/bin/env python3

import time
import decouple
import asyncio
from device_info_lib import DeviceInfo

async def main():
    start_time = time.time()

    # platform_ver = "cisco_ios"
    # platform_ver = "arista_eos"
    platform_ver = "juniper_junos"
    # platform_ver = "linux"

    if platform_ver == "arista_eos":
        commands_file = "commands_files/arista_commands.yml"
        inventory_file = "inventory_files/arista_devices.yml"
        username = decouple.config("USER_NAME")
        password = decouple.config("PASSWORD")
    elif platform_ver == "juniper_junos":
        commands_file = "commands_files/junos_commands.yml"
        inventory_file = "inventory_files/junos_devices.yml"
        username = decouple.config("USER_NAME")
        password = decouple.config("PASSWORD")
    elif platform_ver == "linux":
        commands_file = "commands_files/linux_commands.yml"
        inventory_file = "inventory_files/linux_devices.yml"
        username = decouple.config("LINUX_ADMIN")
        password = decouple.config("PASSWORD")
    else:
        commands_file = "commands_files/cisco_commands.yml"
        inventory_file = "inventory_files/cisco_devices.yml"
        username = decouple.config("USER_NAME")
        password = decouple.config("PASSWORD")

    # creds defined in ./.env file
    global_device_params = {
        "device_type": platform_ver,
        "username": username,
        "password": password,
    }


    device_info = DeviceInfo(inventory_file, commands_file, platform_ver, global_device_params)
    ip_list = device_info.get_devices_list()

    tasks = [asyncio.create_task(device_info.commands_output(ip)) for ip in ip_list]
    results = await asyncio.gather(*tasks)

    for result in results:
        device_info.save_output(result["device_hostname"], result["commands_output"])

    print(f"It took {time.time() - start_time} seconds to run")


if __name__ == "__main__":
    asyncio.run(main())
