import json
import sys

def main(argv):
    ipOurNode = argv[0]
    inputFile = argv[1]


    # get content addresses from one package
    def getAddresses(obj):
        addresses = []

        # if no error only one message which is addr exists
        # if error we have to search for addr message in a list
        try:
            addrCount = int(obj['_source']['layers']['bitcoin']['bitcoin.addr']['bitcoin.addr.count'])
            addressTree = obj['_source']['layers']['bitcoin']['bitcoin.addr']['bitcoin.addr.address_tree']
        except TypeError as err:
            for msg in obj['_source']['layers']['bitcoin']:
                if msg['bitcoin.command'] == 'addr':
                    addrCount = int(msg['bitcoin.addr']['bitcoin.addr.count'])
                    addressTree = msg['bitcoin.addr']['bitcoin.addr.address_tree']

        if addrCount > 1:
            for value in addressTree:
                addresses.append(value['bitcoin.address.address'])
        else:
            addresses.append(addressTree['bitcoin.address.address'])

        # remove last ,
        if addresses != '':
            addresses = addresses[:-1]

        return addresses, addrCount

    # read json file
    with open(inputFile, 'r') as myfile:
        data = myfile.read()

    allMsgs = json.loads(data)
    # incoming messages
    msgsIn = []
    # outgoing messages
    msgsOut = []
    output = []

    # fill lists
    for obj in allMsgs:
        source = obj['_source']['layers']['ip']['ip.src']
        if source != ipOurNode:
            msgsIn.append(obj)
        elif source == ipOurNode:
            msgsOut.append(obj)

    for obj in msgsIn:
        time = int(obj['_source']['layers']['frame']['frame.time_epoch'].split('.')[0])

        # error when no bitcoin protol message; just continue with next messsage
        try:
            contentIn, addrCount = getAddresses(obj)
        except KeyError as err:
            continue

        numberIn = obj['_source']['layers']['frame']['frame.number']

        # search for matching outgoing message
        if addrCount <= 10:
            for addr in contentIn:
                matchOut = {}

                for objOut in msgsOut:
                    timeOut = int(objOut['_source']['layers']['frame']['frame.time_epoch'].split('.')[0])

                    # error when no bitcoin protocol message; just continue with next messsage
                    try:
                        contentOut = getAddresses(objOut)[0]
                    except KeyError as err:
                            continue

                    numberOut = objOut['_source']['layers']['frame']['frame.number']
                    if timeOut < time:
                        continue
                    elif addr in contentOut:
                        # check that there was no message sent in between
                        if matchOut == {} or timeOut < matchOut['time']:
                             matchOut['time'] = timeOut
                             matchOut['address'] = addr
                             matchOut['timeDiff'] = timeOut - time

                # found matching out message
                if matchOut != {}:
                    updated = False
                    toAdd = {'numberIn': numberIn, 'numberOut': numberOut, 'addressSent': matchOut['address'], 'timeDiff': matchOut['timeDiff']}

                    # check for same output
                    for x in output:
                        # update existing entry
                        if x['addressSent'] == toAdd['addressSent'] and x['numberOut'] == numberOut:
                            if x['timeDiff'] > toAdd['timeDiff']:
                                output.remove(x)
                                output.append(toAdd)
                                updated = True
                            else:
                                updated = True

                    if not updated:
                        output.append(toAdd)

    # write output to file
    with open('./output.json', 'w') as myfile:
        if output != []:
            json.dump(output, myfile)
        else:
            myfile.write('No relayed messages detected.')


if __name__ == "__main__":
    main(sys.argv[1:])
