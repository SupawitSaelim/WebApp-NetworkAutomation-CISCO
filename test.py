raw_interface = "gi0/1-24, gi0/3"

raw_interface_list = [interface.strip() for interface in raw_interface.split(',')]

interface_list = []
for raw_interface in raw_interface_list:
    parts = raw_interface.split('/')
    if len(parts) == 2:
        prefix, range_str = parts
        range_parts = range_str.split('-')
        if len(range_parts) == 2:
            start, end = map(int, range_parts)
            interface_list.extend([f"{prefix}/{i}" for i in range(start, end + 1)])
        else:
            interface_list.append(raw_interface)

print("Interface List:", interface_list)
