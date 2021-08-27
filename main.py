import re

import scapy.all as scapy

ANGRYIP_FLAG = [
    '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
    '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00']


def processStr(data):
    pattern = re.compile('^b\'(.*?)\'$', re.S)
    res = re.findall(pattern, str(data))
    final = re.split('\\\\r\\\\n', res[0])
    return final


if __name__ == '__main__':
    isZmap = False
    isAngryip = False
    isMasscan = False

    packets = scapy.rdpcap("masscan.pcap")

    for data in packets:
        if 'TCP' in data:
            # 识别 Zmap
            if (data['TCP'].window == 65535) and (data['IP'].id == 54321):
                isZmap = True
            # 识别 Masscan
            if data['TCP'].window == 1024 and data['TCP'].ack == 0 \
                    and data['IP'].ttl == 255 and data['IP'].len == 40:
                isMasscan = True
        # 识别 Angry IP Scanner
        if 'ICMP' in data:
            if 'Raw' in data:
                items = processStr(data['Raw'].load)
                if len(data['Raw']) == 32 and items == ANGRYIP_FLAG:
                    isAngryip = True

    if isZmap:
        print("Zmap")
    if isAngryip:
        print("Angry IP Scanner")
    if isMasscan:
        print("Masscan")
    if isZmap == False and isAngryip == False and isMasscan == False:
        print("未识别")
