from argparse import ArgumentParser
from src.setup.cmd_handler import CmdHandler
import sys


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

    # Route subparser
    route_parser = subparsers.add_parser("route", help="Initialize a route")
    route_parser.add_argument("--exit-location", type=str, default=None, help="The exit location of the route")
    route_parser.add_argument("--streaming", type=bool, default=False, help="Whether the route is for streaming")
    route_parser.add_argument("--node-count", type=int, default=3, help="The number of nodes in the route")

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

    # Return the parser
    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args(sys.argv[1:])
    CmdHandler(args.command, args)


if __name__ == "__main__":
    main()
