# ShadowClone
ShadowClone allows you to  distribute your long running tasks dynamically across thousands of serverless functions and gives you the results within seconds where it would have taken hours to complete.

You can make full use of the Free Tiers provided by cloud providers and supercharge your mundane cli tools with shadow clone jutsu (Naruto style)!

## Installation
Please visit the wiki for installation and intial configuration instructions

## Usage
```bash
⚡ python shadowclone.py -h
usage: shadowclone.py [-h] -i INPUT [-s SPLITNUM] [-o OUTPUT] -c COMMAND

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
  -s SPLITNUM, --split SPLITNUM
                        Number of lines per chunk of file
  -o OUTPUT, --output OUTPUT
  -c COMMAND, --command COMMAND
                        command to execute

```

## Features
- Extremely fast
- No need to maintain a VPS (or a fleet of it :)) 
- Costs almost nothing per month
	- Compatible with free tiers of most cloud services
- Cloud agnostic 
	- Same script works with AWS, GCP, Azure etc.
- Supports upto 1000 parallel invocations
- Dynamically decide the number of invocations
- Run *any* tool in parallel on the cloud
- Pipe output to other tools 

## Comparison
This tool was inspired by the awesome [Axiom](https://github.com/pry0cc/axiom) and [Fleex](https://github.com/FleexSecurity/fleex) projects and goes beyond the concept of VPS for running the tools by using serverless functions and containers. 

| Features              | Axiom/Fleex             | ShadowClone   |
| --------------------- | ----------------------- | ------------- |
| Instances             | 10-100s*                 | 1000s         |
| Cost                  | Per instance/per minute | Mostly Free** |
| Startup Time          | 4-5 minutes             | 2-3 seconds   |
| Idle Cost                 | $++                     | Free          |
| On Demand Scalability | No                      |        ∞        |

`*`Most cloud providers do not allow spinning up too many instances by default, so you are limited to around 10-15 instances at max. You have to make a request to the support to increase this number. 

`**` AWS & Azure allow 1 million invocations per month for free. Google allows 2 million invocations per month for free. You will be charged only if you go above these limits


## Demo
DNS Bruteforcing using a 43mb file - 34 seconds

[![asciicast](https://asciinema.org/a/lISleX6xohoiEx8N7PozjySEq.svg)](https://asciinema.org/a/lISleX6xohoiEx8N7PozjySEq)

Running httpx on 94K subdomains in 1 min

[![asciicast](https://asciinema.org/a/GSwuqyd9X4JfXGlqQEFiDdefi.svg)](https://asciinema.org/a/GSwuqyd9X4JfXGlqQEFiDdefi)

## References
Lithops documentation


### Free Tiers

| Cloud Provider   | Free Allowance                                                                       | Link                                                                                           |
| ---------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Google Functions | 2 Million invocations, 400,000 GB-seconds per month                             | [Google Cloud Free Program](https://cloud.google.com/free/docs/gcp-free-tier/#cloud-functions) |
| AWS  Lambda      | 1 Million invocations,  **Up to 3.2 million seconds** of compute time per month | [Free Cloud Computing Services - AWS Free Tier](https://aws.amazon.com/free/)                  |
| Azure Functions  | 1 Million   invocations                                                         | [Microsoft Azure Free Services](https://azure.microsoft.com/en-ca/free/)                                                                                               |

Obviously, you can make any number of function invocations per month. The table above only shows how many invocations are free.

### Similar Tools
- [Axiom](https://github.com/pry0cc/axiom)
- [Fleex](https://github.com/FleexSecurity/fleex)
- [gopherblazer](https://github.com/0xdevalias/gopherblazer)
