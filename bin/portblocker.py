#!/usr/bin/env python3
import argparse
import sys, os
import errno, pathlib, re
import datetime, time
import logging
import ipaddress
import iptc

parser = argparse.ArgumentParser(description="Autoblock IP addresses with iptables")
subparsers = parser.add_subparsers(help='commands', dest='command')

## Monitor subparser
parser_monitor = subparsers.add_parser('monitor', help='Monitor for blocked connections on specified port(s)')
parser_monitor.add_argument('-p', '--port', help='Ports to monitor', metavar='KEY', nargs='+', required=True)
parser_monitor.add_argument('-c', '--chain', help='IPTables chain to monitor', metavar='CHAIN', required=True)


## Block subparser
parser_block = subparsers.add_parser('block', help='Automatically block IPs that attempt connections on specified port(s)')
parser_block.add_argument('-p', '--port', help='Ports to monitor', metavar='KEY', nargs='+', required=True)
parser_block.add_argument('-c', '--chain', help='IPTables chain to monitor', metavar='CHAIN', required=True)
parser_block.add_argument('--whitelist', help='IP addresses/CIDR ranges to whitelist', metavar='CIDR', nargs='+')

args = parser.parse_args()



def checkIp(address):
    try:
        ipAddr = ipaddress.ip_address(address)
    except ValueError:
        logging.error("Invalid IP: " + address)
        sys.exit(1)
    return ipAddr

def enumCidr(cidr):
    try:
        ipRange = ipaddress.ip_network(CIDR)
    except ValueError:
        logging.error("Invalid CIDR range: " + address)
        sys.exit(1)
    return ipRange


def main():
    if args.whitelist:
        addrList = []
        for range in args.whitelist:
            cidrRange = enumCidr(range)
            for addr in cidrRange:
                ip = checkIp(addr)
            addrList.append(range)

if __name__ == '__main__':
    main()
