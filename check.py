from scapy.all import get_windows_if_list

interfaces = get_windows_if_list()

print("Available interfaces with names and GUIDs:\n")
for iface in interfaces:
    print(f"- Name: {iface['name']}")
    print(f"  Description: {iface['description']}")
    print(f"  GUID: {iface['guid']}")
    print()
