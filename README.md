# SniPy
**SniPy is a python asyncio based SNI proxy server**

Capabilities:
- HTTP/HTTPS proxification (on port 80 and 443 respectively)
- socks5 proxy for upstream connection 


## Installation
```bash
git https://github.com/amirdaaee/SniPy
cd SniPy
pip install -r ./requirements.txt
```
or wait until `build.py` is pushed!

## Usage
`python Server.py --help` will give you almost anything you need to config and run server.
SniPy is completely dependent on environmental variables for configuration, or you can assign them in `.env` file in project root directory.
`python Server.py --list-env` gives a list of available configuration variables.

## Todo
- [ ] tests
- [ ] completing readme document docker



## Contributing
Pull requests are highly welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.