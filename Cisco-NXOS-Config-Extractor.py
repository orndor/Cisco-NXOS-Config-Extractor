# Pyhton
# Author: Rob O
# 18 Feb 2024
# Given a Cisco NXOS config file, this script extracts all configurations which pertain to a particular VRF: 
#   Interface VRF Members, VLANs, VRF Context & Static Routes, BGP configuration, OSPF Processes, AS-Path filter lists, Route-Maps, Community-lists, Prefix-lists, and all trunk interfaces.
# Libraries: CiscoConfParse, re

from ciscoconfparse import CiscoConfParse
import re

def get_interfaces(ios_config_file, vrf_name, output_file):
    vlan_numbers = list()
    parse = CiscoConfParse(ios_config_file)

    vrf_members = parse.find_parents_w_child('^interf', fr'^\s*vrf\s+member\s+{vrf_name}')
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for interface_name in vrf_members:
            interface = parse.find_objects(fr'{interface_name}\b')
            for obj in interface:
                file.write('!\n' + obj.text + '\n')
                for child in obj.all_children:
                    file.write(child.text + '\n')
        file.write("!\n!\n")
        for interface_name in vrf_members:
            match = re.search(r'Vlan(\d+)', interface_name)
            if match:
                vlan_number = match.group(1)
                vlan_numbers.append(int(vlan_number))

    return(vlan_numbers)

def get_vlans(ios_config_file, vlan_numbers, output_file):
    parse = CiscoConfParse(ios_config_file)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for vlan_number in vlan_numbers:
            vlan_pattern = re.compile(fr'^vlan\s+{vlan_number}\b')
            vlan_objects = parse.find_objects(vlan_pattern)
            for vlan_object in vlan_objects:
                file.write(vlan_object.text + '\n')
                for child in vlan_object.all_children:
                    file.write(child.text + '\n')
        file.write("!\n!\n")

def get_vrfContext(ios_config_file, vrf_name, output_file):
    parse = CiscoConfParse(ios_config_file)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        context = parse.find_objects(fr'vrf context {vrf_name}\b')
        for obj in context:
            if obj:
                file.write(obj.text + '\n')
                for child in obj.all_children:
                    file.write(child.text + '\n')
        file.write("!\n!\n")

def get_BGP(ios_config_file, vrf_name, output_file):
    # Get all the BGP config for a given VRF; return the filter-list and route-map names
    filter_list = list()
    routemap_list = list()
    current_depth = 1
    depth = 1
    pattern_filterlist = re.compile(r'filter-list\s+(\S+)\s+(in|out)')
    pattern_routemap   = re.compile(r'route-map\s+(\S+)\s+(in|out)')

    parse = CiscoConfParse(ios_config_file, syntax='nxos', factory=True)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for bgp_obj in parse.find_objects(r"^router\s+bgp"):
            file.write(bgp_obj.text + '\n')
            for vrf_obj in bgp_obj.children:
                if f"vrf {vrf_name}" in vrf_obj.text:
                    file.write(vrf_obj.text + '\n')
                    if current_depth <= depth:
                        for child in vrf_obj.all_children:
                            if 'filter-list' in child.text:
                                match = pattern_filterlist.search(child.text)
                                if match:
                                    filter_name = match.group(1)
                                    filter_list.append(filter_name)
                            if 'route-map' in child.text:
                                match = pattern_routemap.search(child.text)
                                if match:
                                    filter_name = match.group(1)
                                    routemap_list.append(filter_name)
                            file.write("  " * current_depth + child.text + '\n')
                            current_depth + 1
        file.write("!\n!\n")
    return filter_list, routemap_list

def get_ospfConfig(ios_config_file, vrf_name, output_file):
    pattern_routemap = re.compile(r'route-map\s+(\S+)')
    routemap_list = list()

    parse = CiscoConfParse(ios_config_file)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for ospf_obj in parse.find_objects(fr'^router ospf \d+$'):
            file.write(ospf_obj.text + '\n')
            for vrf_obj in ospf_obj.children:
                if f"vrf {vrf_name}" in vrf_obj.text:
                    file.write(vrf_obj.text + '\n')
                    for child in vrf_obj.all_children:
                        file.write(child.text + '\n')
                        if 'route-map' in child.text:
                            match = pattern_routemap.search(child.text)
                            if match:
                                filter_name = match.group(1)
                                routemap_list.append(filter_name)
        file.write("!\n!\n")
    return(routemap_list)

def get_filter(filter_lists, ios_config_file, output_file):
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for filter_name in filter_lists:
            pattern = re.compile(fr'ip\s+as-path\s+access-list\s+{filter_name}\b')
            with open(ios_config_file, 'r') as input_file:
                for line in input_file:
                    if pattern.search(line):
                        file.write(line.strip() + '\n')
        file.write("!\n!\n")

def get_rm(route_maps, ios_config_file, output_file):
    community_list = list()
    prefixlist_list = list()

    parse = CiscoConfParse(ios_config_file)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for route_map_name in route_maps:
            route_map = parse.find_objects(r'^route-map\s+{}\b'.format(route_map_name))
            for obj in route_map:
                if obj:
                    file.write(obj.text + '\n')
                    for child in obj.all_children:
                        file.write(child.text + '\n')
                        # Check if the line starts with "match ip address prefix-list" using regex
                        prefix_list_match = re.match(r'^\s*match\s+ip\s+address\s+prefix-list\s+(\S+)', child.text)
                        if prefix_list_match:
                            prefix_list_name = prefix_list_match.group(1)
                            prefixlist_list.append(prefix_list_name)
                        # Check if the line starts with "match community" using regex
                        match_community_match = re.match(r'^\s*match\s+community\s+(\S+)', child.text)
                        if match_community_match:
                            # If a match is found, append the next word to a list
                            community_name = match_community_match.group(1)
                            community_list.append(community_name)
        file.write("!\n!\n")
    return(community_list, prefixlist_list)

def get_community_lists(community_lists, ios_config_file, output_file):
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for community_name in community_lists:
            pattern = re.compile(fr'ip\s+community-list\s+standard\s+{community_name}\b')
            with open(ios_config_file, 'r') as input_file:
                for line in input_file:
                    if pattern.search(line):
                        file.write(line.strip() + '\n')
        file.write("!\n!\n")

def get_prefix_lists(prefix_list, ios_config_file, output_file):
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        for prefixlist_name in prefix_list:
            pattern = re.compile(fr'ip\s+prefix-list\s+{prefixlist_name}\b')
            with open(ios_config_file, 'r') as input_file:
                for line in input_file:
                    if pattern.search(line):
                        file.write(line.strip() + '\n')
        file.write("!\n!\n")

def get_trunks(ios_config_file, output_file):
    parse = CiscoConfParse(ios_config_file)
    with open(output_file, 'a') as file:
        file.write("!\n!\n")
        trunk_ints = parse.find_parents_w_child('^interf', 'switchport mode trunk')
        for interface_name in trunk_ints:
            interface = parse.find_objects(fr'{interface_name}\b')
            for obj in interface:
                file.write(obj.text + '\n')
                for child in obj.all_children:
                    file.write(child.text + '\n')
        file.write("!\n!\n")

# Main
def main():
    # Specify global variables and values
    ios_config_file = "insert-file-name-here-in-present-directory"
    vrf_name = "insert-VRF-name-here"

    # Specify output filename
    output_file = f"{ios_config_file}_{vrf_name}.txt"

    # Get the interfaces used for BGP peering for the VRF
    vlan_numbers = get_interfaces(ios_config_file,vrf_name, output_file)

    # Get vlan configurations
    get_vlans(ios_config_file, vlan_numbers, output_file)

    # Get vrf Context config
    get_vrfContext(ios_config_file, vrf_name, output_file)

    # Get the BGP configuration for the specificed VRF, return filter-list and route-map names.
    filter_lists, bgp_route_maps = (get_BGP(ios_config_file,vrf_name, output_file)) 

    # Get OSPF configurations
    ospsf_routemaps = get_ospfConfig(ios_config_file, vrf_name, output_file)

    # Get the as-path filter lists used for BGP peers within the specificed VRF
    get_filter (filter_lists, ios_config_file, output_file) # missing one of the as-path lists in the Avaya config

    # Take all discovered route-maps combine them, and de-dup it, for ingestion in get_rm function
    route_maps = list(set(ospsf_routemaps + bgp_route_maps))

    # Get the route-maps used for BGPs within the specified VRF, also return any community lists and prefix lists used as filters.
    community_lists, prefix_list = get_rm (route_maps, ios_config_file, output_file) 

    # Get the full community-lists used for this VRFs peers.    
    get_community_lists(community_lists, ios_config_file, output_file)

    # Get the full prefix-lists used for this VRF peers.
    get_prefix_lists(prefix_list, ios_config_file, output_file) 

    # Get trunk interfaces
    get_trunks(ios_config_file, output_file)

# Call Main
if __name__ == "__main__":
    main()