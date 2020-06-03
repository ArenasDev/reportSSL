# reportSSL

Python tool to analyze SSL/TLS vulnerabilities and generate image proof of all issues.

## Getting Started

To use reportSSL python 3.X is required.

### Installing

Install all requirements:

```
pip install -r requirements.txt
```

## Running the tool

For silent mode (will print everything that is being checked and if it is vulnerable)

```
python reportSSL.py www.google.es 443
```
![Silent Mode](/silentSample.png)

For verbose mode (will print everything that would be printed in silent mode, plus every image that is generated in the console)

```
python reportSSL.py --verbose www.google.es 443
```
![Image Sample](/imageSample.png)