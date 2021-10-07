import asyncio
import io
from abc import abstractmethod
from asyncio import StreamReader, StreamWriter

import aiosocks
import dpkt.http
import dpkt.ssl

import SniPy.Config
from SniPy.Logging import logger


class SniServer:
    port: int = None
    local_reader: StreamReader = None
    local_writer: StreamWriter = None
    remote_reader: StreamReader = None
    remote_writer: StreamWriter = None
    connection_info = None

    def __init__(self, *args, **kwargs):
        self.factory_args = args
        self.factory_kwargs = kwargs
        self.ip = SniPy.Config.Settings.local_ip.__str__()
        self.chunk_size = SniPy.Config.Settings.pipe_chunk
        self.remote_connect_event = asyncio.Event()
        self.proxy = {
            'address': aiosocks.Socks5Addr(SniPy.Config.Settings.proxy_host, SniPy.Config.Settings.proxy_port),
            'auth': aiosocks.Socks5Auth(
                SniPy.Config.Settings.proxy_auth_username,
                SniPy.Config.Settings.proxy_auth_password) if SniPy.Config.Settings.proxy_auth_username else None,
            'resolve': SniPy.Config.Settings.proxy_resolve
        } \
            if SniPy.Config.Settings.proxy else None

    async def factory(self, reader, writer):
        await self.__class__(*self.factory_args, **self.factory_kwargs).handle_connection(reader, writer)

    async def start(self):
        await asyncio.start_server(self.factory, host=self.ip, port=self.port)
        logger.warning(f'server started at {self.ip}:{self.port}')

    async def handle_connection(self, reader: StreamReader, writer: StreamWriter):
        logger.debug('handling new connection')
        self.local_reader = reader
        self.local_writer = writer
        pipe1 = self.pipe(self.local_reader, self.remote_writer)
        pipe2 = self.pipe(self.remote_reader, self.local_writer)
        await asyncio.gather(pipe1, pipe2)
        logger.debug('connection done')

    async def extract_info_(self, packet):
        writer = self.local_writer
        self.connection_info = {'peername': writer.get_extra_info('peername')}
        await self.extract_info(packet)
        logger.debug(f'connection info:{self.connection_info}')

    @abstractmethod
    async def extract_info(self, packet):
        raise NotImplementedError

    async def remote_connect(self, initial_packet):
        try:
            await self.extract_info_(initial_packet)
            assert self.connection_info['server_name']
        except Exception as e:
            logger.error(f'error extracting connection information from packet {initial_packet}')
            raise e

        if self.proxy:
            logger.info(f"connection from {self.connection_info['peername']}:{self.port} -> "
                        f"{self.proxy['address']} -> "
                        f"{self.connection_info['server_name']}")
            reader, writer = await aiosocks.open_connection(
                proxy=self.proxy['address'],
                proxy_auth=self.proxy['auth'],
                remote_resolve=self.proxy['resolve'],
                dst=(self.connection_info['server_name'], self.port)
            )
        else:
            logger.info(f"{self.connection_info['peername']}:{self.port} ->"
                        f"{self.connection_info['server_name']}")
            reader, writer = await asyncio.open_connection(
                self.connection_info['server_name'],
                self.port
            )
        self.remote_reader, self.remote_writer = reader, writer
        self.remote_connect_event.set()

    async def pipe(self, reader: StreamReader, writer: StreamWriter):
        init_remote = False
        if not writer:
            # no remote connection yet
            init_remote = True
        elif not reader:
            logger.debug('waiting for remote connection')
            await self.remote_connect_event.wait()
            reader = self.remote_reader
        try:
            while not reader.at_eof():
                data = await reader.read(self.chunk_size)
                logger.trace(f'read {len(data)}bytes data')
                if init_remote:
                    logger.debug('initiating remote connection')
                    await self.remote_connect(data)
                    writer = self.remote_writer
                    init_remote = False
                writer.write(data)
                logger.debug(f'wrote {len(data)}bytes data')
        except ConnectionError as e:
            logger.debug(f'connection error: {e.strerror}')
        finally:
            writer.close()


#
class SniServerHTTP(SniServer):
    port = 80

    async def extract_info(self, packet):
        buffer = io.BytesIO(packet)
        buffer.readline()
        info = dpkt.http.parse_headers(buffer)
        self.connection_info['server_name'] = info['host']


class SniServerHTTPS(SniServer):
    port = 443

    async def extract_info(self, packet):
        try:
            info = dpkt.ssl.TLS(packet)
            host = {x: y for x, y in dpkt.ssl.TLSHandshake(info.records[0].data).data.extensions}[0][5:]
            self.connection_info['server_name'] = host.decode('ascii')
            assert host
        except Exception as e:
            raise e
