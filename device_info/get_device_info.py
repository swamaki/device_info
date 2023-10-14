#!/usr/bin/env python3

import time
import asyncio

from device_info_lib import DeviceInfo, SetConnectionParams

# from device_info.device_info_lib import DeviceInfo, SetConnectionParams

# from myscripts.device_info.device_info_lib import DeviceInfo, SetConnectionParams


async def main():
    start_time = time.time()

    # device_type = "cisco_ios"
    # device_type = "arista_eos"
    device_type = "juniper_junos"
    # device_type = "linux"

    connection_params = SetConnectionParams(device_type)
    device_params = connection_params.set_params()
    inventory_file = device_params["inventory_file"]
    commands_file = device_params["commands_file"]
    global_device_params = device_params["global_device_params"]

    device_info = DeviceInfo(inventory_file, commands_file, global_device_params)
    ip_list = device_info.get_devices_list()

    if device_type == "linux":  # use netmiko if it's a linux platform
        tasks = [
            asyncio.create_task(device_info.commands_output_netmiko(ip))
            for ip in ip_list
        ]
        results = await asyncio.gather(*tasks)
    else:
        tasks = [asyncio.create_task(device_info.commands_output(ip)) for ip in ip_list]
        results = await asyncio.gather(*tasks)

    for result in results:
        device_info.save_output(result["device_hostname"], result["commands_output"])

    print(f"It took {time.time() - start_time} seconds to run")


if __name__ == "__main__":
    asyncio.run(main())
