# bitcoinRelayTimeAddr
Takes information gathered with wireshark and calculates the relay time of an addr message in the bitcoin network.

## Run the script
`addrDiff.py <p1> <p2>`

Input parameter:\
 `<p1>`: The ip from the bitcoin node we were sniffing in wireshark.\
 `<p2>`: Json file exported from wireshark with no-duplicate-keys option: First filter the captured packets with bitcoin.addr in wireshark. Then export pcapng file.   
         As last step create the json file with tshark e.g.: tshark -T json --no-duplicate-keys -r test1NoDup.pcapng > test1NoDup.json.
