__author__ = "Sam Gardner"
__version__ = "4.10.1"

import json, logging, os, sys
from argparse import ArgumentParser
from src.setup.CmdHandler import CmdHandler

logging.basicConfig(level=logging.DEBUG)


class ErroredArgumentParser(ArgumentParser):
    def error(self, message):
        print(f"Error: {message}\n")
        self.print_help()
        sys.exit(2)


def create_argument_parser() -> ArgumentParser:
    parser = ErroredArgumentParser(prog="snetwork", description="A distributed anonymous overlay network")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Keygen subparser
    key_gen_parser = subparsers.add_parser("keygen", help="Generate static public keys for current profile")
    key_gen_parser.add_argument("--force", action="store_true", help="Force the generation of new keys")

    # Route subparser
    route_parser = subparsers.add_parser("route", help="Initialize a route")
    route_parser.add_argument("--exit-location", type=str, default=None, help="The exit location of the route")
    route_parser.add_argument("--streaming", type=bool, default=False, help="Whether the route is for streaming")
    route_parser.add_argument("--node-count", type=int, default=3, help="The number of nodes in the route")

    # Join subparser
    join_parser = subparsers.add_parser("join", help="Join the network")

    # Storage subparser
    storage_parser = subparsers.add_parser("storage", help="Interact with the storage system")

    # Storage sub-subparsers
    storage_subparsers = storage_parser.add_subparsers(dest="storage_command", required=True, help="Available storage commands")

    # Storage "put" subparser
    storage_put_parser = storage_subparsers.add_parser("put", help="Put a file into the storage system")
    storage_put_parser.add_argument("--path", type=str, required=True, help="The path to the file to put")
    storage_put_parser.add_argument("--protocol", type=str, required=True, help="The protocol to use")
    storage_put_parser.add_argument("--r", type=int, default=3, help="The replication factor")

    # Storage "get" subparser
    storage_get_parser = storage_subparsers.add_parser("get", help="Get a file from the storage system")
    storage_get_parser.add_argument("--path", type=str, required=True, help="The path to the file to get")

    # Storage "del" subparser
    storage_del_parser = storage_subparsers.add_parser("del", help="Delete a file from the storage system")
    storage_del_parser.add_argument("--path", type=str, required=True, help="The path to the file to delete")

    # Storage "rename" subparser
    storage_rename_parser = storage_subparsers.add_parser("rename", help="Rename a file in the storage system")
    storage_rename_parser.add_argument("--old-path", type=str, required=True, help="The old path to the file")

    # Directory node subparser
    directory_node_parser = subparsers.add_parser("directory", help="Start a directory node")

    # Reset node subparser
    directory_node_parser = subparsers.add_parser("reset", help="Reset the node")

    # Return the parser
    return parser


def main():
    if not os.path.exists("./_keys"): os.mkdir("./_keys")
    if not os.path.exists("./_cache"):
        os.mkdir("./_cache")
    if not os.path.exists("./_cache/dht_cache.json"):
        json.dump([], open("./_cache/dht_cache.json", "w"))

    if len(sys.argv) > 1:
        logging.debug(f"Don't use program arguments here - use the interactive shell.")
        sys.exit(1)

    parser = create_argument_parser()
    while True:
        command = input("> ")
        if command == "exit": break
        args = parser.parse_args(command.split())
        CmdHandler(args.command, args)


if __name__ == "__main__":
    main()
