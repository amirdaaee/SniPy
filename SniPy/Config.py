import atexit
import os.path
import pickle
from ipaddress import IPv4Address
from typing import Optional

from pydantic import BaseSettings, conint, Field, validator

from SniPy.Logging import logger
from SniPy.Logging import reload as relog

port_type = conint(ge=0, le=65353)


class BaseSettingType(BaseSettings):
    local_ip: IPv4Address = Field(title='local ip to bind', default='127.0.0.1')
    workers: int = Field(title='number of workers', default=1)
    pipe_chunk: int = Field(title='chunk size for socket packet relay', default=2 ** 14)
    proxy: bool = Field(title='use socks5 to connect to the remote host', default=False)
    proxy_host: Optional[str] = Field(title='ip address of the socks5 proxy server', default=None)
    proxy_port: Optional[port_type] = Field(title='port of the socks5 proxy server', default=None)
    proxy_auth_username: Optional[str] = Field(title='proxy authentication username', default=None)
    proxy_auth_password: Optional[str] = Field(title='proxy authentication password', default=None)
    proxy_resolve: bool = Field(title='resolve hostname over proxy', default=False)

    class Config:
        env_prefix = 'SNIPY__'

    @staticmethod
    def _proxy_is_defined(v, values, field):
        if values['proxy'] and not v:
            raise ValueError(f'{field.name} should be defined')
        return v

    # noinspection PyMethodParameters
    @validator('proxy_host')
    def proxy_host_defined(cls, v, values, field):
        return cls._proxy_is_defined(v, values, field)

    # noinspection PyMethodParameters
    @validator('proxy_port')
    def proxy_port_defined(cls, v, values, field):
        return cls._proxy_is_defined(v, values, field)


class Configuration:
    RUNTIME_FILE = './.config.runtime'

    @staticmethod
    def global_config(config):
        type(config)
        relog()

    @classmethod
    def load(cls):
        def _clean_exit():
            if os.path.isfile(cls.RUNTIME_FILE):
                os.remove(cls.RUNTIME_FILE)

        data = BaseSettingType(_env_file=None)
        with open(cls.RUNTIME_FILE, 'wb') as f_:
            pickle.dump(data.dict(), f_)
        atexit.register(_clean_exit)
        global _settings
        _settings = data
        cls.global_config(data)
        return cls


def __getattr__(name):
    if name == 'Settings':
        global _settings
        if _settings is not None:
            logger.trace('reading configuration from cache')
            return _settings
        if os.path.isfile(Configuration.RUNTIME_FILE):
            logger.trace('reading configuration from runtime file')
            with open(Configuration.RUNTIME_FILE, 'rb') as f_:
                _settings = pickle.load(f_)
                return _settings
        else:
            logger.warning('configuration is not initiated yet')
            return None


_settings: Optional[BaseSettingType] = None
Settings: Optional[BaseSettingType]
