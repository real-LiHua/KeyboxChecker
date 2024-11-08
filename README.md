# Batch keybox checker
[中文](docs/README.zh-CN.md)
## Requirements
Rust (Compile-Time)  
Python >= 3.8  
For restricted network environments, it may be necessary to set the web proxy environment variables:  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`. (See: [Requests documentation](https://requests.readthedocs.io/en/latest/user/advanced/#proxies) for details)

## Install
```bash
pip install keyboxchecker
```

## Usage
```bash
usage: keyboxchecker [-h] [-a] [-o OUTPUT] [-p PATH]

options:
  -h, --help            show this help message and exit
  -a, --aosp            Categorizes the AOSP keybox as "Survivor" with a default value of "False"
  -o OUTPUT, --output OUTPUT
                        Resulting output directory, defaults to current Directory
  -p PATH, --path PATH  Directory where keybox is located, defaults to current directory
```

## Uninstall
```bash
pip uninstall keyboxchecker
```

## Credits
[KimmyXYC/KeyboxChecker](https://github.com/KimmyXYC/KeyboxChecker)
