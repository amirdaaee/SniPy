import argparse
import asyncio
import copy
import os

import aiorun
import atexit
import dotenv

import SniPy.Config
import SniPy.Core
from SniPy.Logging import logger


def read_cli():
    parser = argparse.ArgumentParser(description='Start a DNS proxy server')
    parser.add_argument('--env-file', default=None, type=str, help='path to env file for configuration',
                        metavar='path')
    parser.add_argument('--list-env', action='store_true', help='show all available env. variables options')
    args = parser.parse_args()
    if args.env_file:
        dotenv.load_dotenv(args.env_file)

    return args


class HelpPrinter:
    sep_1 = '=' * 70
    sep_2 = '-' * 30
    sep_3 = '-' * 20
    sep_4 = ':' * 15

    @classmethod
    def print_list_env(cls):
        def _print_env_data(data: dict):
            data: dict = copy.deepcopy(data)
            print(', '.join(data.pop('env_names')).upper())
            for i__ in ['title', 'default', 'type']:
                v_ = data.pop(i__, None)
                if v_:
                    print('\t', i__, ':', v_)
            for i__, v_ in data.items():
                print('\t', i__, ':', v_)
            print()

        print(cls.sep_1)
        print('server config options:')
        print(cls.sep_2)
        SniPy.Config.Configuration.load()
        conf = SniPy.Config.Settings.schema()['properties']
        plugin_conf = {}
        for i_, j_ in conf.items():
            _print_env_data(j_)


def main():
    def _clean_exit():
        logger.warning('server shutdown')

    atexit.register(_clean_exit)
    SniPy.Config.Configuration.load()
    print(f'configuration: {SniPy.Config.Settings.json()}')
    loop = asyncio.get_event_loop()
    loop.create_task(SniPy.Core.SniServerHTTPS().start())
    loop.create_task(SniPy.Core.SniServerHTTP().start())
    workers = SniPy.Config.Settings.workers
    aiorun.run(loop=loop, executor_workers=workers)


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    args_ = read_cli()
    if args_.list_env:
        HelpPrinter.print_list_env()
    else:
        main()
