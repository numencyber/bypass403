# bypass403
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
![Follow on Twitter](https://img.shields.io/twitter/follow/numencyber?style=social)

**python script bypass 403.The methods are as follows.**
- modify headers
- modify uri
- brute directory

## Usage
```
python3 bypass403.py -u https://www.example.com/admin
python3 bypass403.py -l 403.txt
## the output file
python3 bypass403.py -u https://www.example.com/admin -o example.txt
```

## Feature
- Using Asynchronous aiohttp, scanning speed is fast.
- Combine many payloads found in twitter, github and personal projects.

## Installation
```
git clone https://github.com/NumencyberLabs/bypass403.git
cd bypass403
pip3 install -r requirements.txt
python3 bypass403.py -u https://www.example.com/admin
```

## Reference
https://github.com/iamj0ker/bypass-403  
https://github.com/sting8k/BurpSuite_403Bypasser  
https://github.com/lobuhi/byp4xx  
https://github.com/Dheerajmadhukar/4-ZERO-3/blob/main/403-bypass.sh


