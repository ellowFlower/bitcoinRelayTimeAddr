#!/usr/bin/env python3

import json
import os
import sys
import numpy

# returns information about the relay time of addresses
def addr_relay_time(ip_our_node, input_file):
    output_all = []  # {'frame_number_in':, 'frame_number_out':, 'address_sent':, 'relay_time':}
    output_time_diff = []  # just the relay_time

    with open(input_file, 'r') as f:
        data = f.read()

    all_msgs = json.loads(data)
    # msgs_in: all incoming messages; msgs_out: all outgoing messages
    msgs_in, msgs_out = prepare_information(all_msgs, ip_our_node)
    msgs_in.reverse()

    # try to find for every address sent to us the fitting outgoing messages;
    # if no outgoing message is found just ignore the incoming address
    for msg_in in msgs_in:
        time_in = int(msg_in['time'])
        for address_in in msg_in['addresses']:
            for msg_out in msgs_out:
                time_out = int(msg_out['time'])
                if address_in in msg_out['addresses'] and time_out > time_in:
                    time_diff = time_out - time_in
                    output_all.append({'frame_number_in': msg_in['frame_number'], 'frame_number_out': msg_out['frame_number'], 'address_sent': address_in, 'relay_time': time_diff})
                    output_time_diff.append(time_diff)
                    msg_out['addresses'].remove(address_in)

    median = numpy.median(output_time_diff)
    mean = numpy.mean(output_time_diff)
    output_time_diff = sorted(output_time_diff)

    return output_all, output_time_diff, median, mean

# get the addresses sent in an addr message
# returns addresses with the timestamp
def get_sent_addresses(addr_obj, address_count):
    addresses = []

    if address_count > 1:
        for x in addr_obj['bitcoin.addr']['bitcoin.addr.address_tree']:
            addresses.append(x['bitcoin.address.address'] + '; ' + x['bitcoin.addr.timestamp'])
    else:
        addresses.append(addr_obj['bitcoin.addr']['bitcoin.addr.address_tree']['bitcoin.address.address'] + '; ' + addr_obj['bitcoin.addr']['bitcoin.addr.address_tree']['bitcoin.addr.timestamp'])
    return addresses


# get the relevant information from the json file we get from wireshark
def prepare_information(all_msgs, ip_our_node):
    msgs_in = []
    msgs_out = []
    address_count = -1
    addr_obj = {}

    for msg in all_msgs:
        # maybe there is no bitcoin message
        try:
            bitcoin_obj = msg['_source']['layers']['bitcoin']
        except KeyError:
            continue

        # maybe there are more than one bitcoin message sent; only one is an addr message
        try:
            address_count = int(bitcoin_obj['bitcoin.addr']['bitcoin.addr.count'])
            addr_obj = bitcoin_obj
        except TypeError:
            for bitcoin_msg in bitcoin_obj:
                if bitcoin_msg['bitcoin.command'] == 'addr':
                    address_count = int(bitcoin_msg['bitcoin.addr']['bitcoin.addr.count'])
                    addr_obj = bitcoin_msg
        # no addr message found
        except KeyError:
            continue

        # add the addresses
        if address_count != -1 and address_count <= 10:
            addresses = get_sent_addresses(addr_obj, address_count)  # addresses with timestamp

            to_add = {'frame_number': msg['_source']['layers']['frame']['frame.number'], 'address_count': address_count, 'time': int(msg['_source']['layers']['frame']['frame.time_epoch'].split('.')[0]), 'addresses': addresses}

            if msg['_source']['layers']['ip']['ip.src'] != ip_our_node:
                msgs_in.append(to_add)
            else:
                msgs_out.append(to_add)

    return msgs_in, msgs_out


if __name__ == '__main__':
    # analyse multiple files
    # usage: ./addrRelayTime <own_ip> <directory with json files>
    own_ip = sys.argv[1]
    all_time_diffs = []
    for file in os.scandir(sys.argv[2]):
        print(f'file: {file.path}')
        output_all, output_time_diff, median, mean = addr_relay_time(own_ip, file.path)
        print(f'number of addresses: {len(output_all)}')
        print(output_all)
        print(f'time difference: {output_time_diff}\nmedian: {median}\nmean: {mean}\n')
        print(f'median: {median}\nmean: {mean}\n')
        all_time_diffs.extend(output_time_diff)

    print(f'all files together')
    print(f'mean: {numpy.mean(all_time_diffs)}')
    print(f'median: {numpy.median(all_time_diffs)}')





