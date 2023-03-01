import modal
from invoke import run
import numpy as np
import click
import os
import random
import string
import sys
import datetime


stub = modal.Stub("shadowclone")
vol = modal.SharedVolume().persist("shadowclone")
# nucleivol = modal.SharedVolume().persist("nuclei-templates")

def printerr(msg):
    sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] +" " + msg + "\n")


def splitter(filename, split_factor):
    with open(filename, 'r') as f:
        data = f.read()

    lines = data.split('\n')

    arrays = []

    for i in range(0, len(lines), split_factor):
        lines_group = lines[i:i+split_factor]
        arrays.append(np.array(lines_group))

    return arrays


shadowclone_image = (modal.Image.debian_slim().apt_install(["curl","unzip"]).run_commands(
    ["pip install invoke", 
    "curl -LO https://github.com/projectdiscovery/httpx/releases/download/v1.2.5/httpx_1.2.5_linux_amd64.zip",
    "unzip httpx_1.2.5_linux_amd64.zip -d /usr/local/bin/",
    "curl -LO https://github.com/projectdiscovery/nuclei/releases/download/v2.8.7/nuclei_2.8.7_linux_amd64.zip",
    "unzip nuclei_2.8.7_linux_amd64.zip -d /usr/local/bin/"]))

@stub.function(image=shadowclone_image, shared_volumes={"/root/shadowclone/":vol})
def execute_command(input_array, **kwargs):
    from invoke import run
    import uuid
    import os
    
    output_file = str(uuid.uuid4())
    outpath = "/root/shadowclone/scans/" + kwargs["scan_id"]
    command = kwargs["command"]
    
    if not os.path.exists(outpath):
        os.makedirs(outpath)
    
    if kwargs["nosplit"]:
        nosplit = kwargs["nosplit"]
        if not os.path.exists(nosplit):
            print("[ERROR] File not found:"+nosplit)
            exit(0)    
    else:
        nosplit = None
    
    with open('/tmp/infile', 'w') as f:
        for item in input_array:
            f.write(str(item) + '\n')
    results = run(command.format(INPUT="/tmp/infile", OUTPUT=os.path.join(outpath, output_file), NOSPLIT=nosplit))
    return results.stdout


@click.command()
@click.option('-i', '--input-file', required=True, help='File that you want to split and distribute')
@click.option('-s', '--split-factor',required=False, default=100  ,help='Split factor', type=int)
@click.option('-o', '--output-file',required=False, help='Output file name')
@click.option('-c', '--command', required=True, help='Command to execute')
@click.option('--no-split',required=False, default = None, help='File to be used without splitting')
def shadowclone(input_file, split_factor, output_file, command, no_split):
    if os.path.exists(input_file):
        lines = splitter(input_file, split_factor)
    else:
        printerr("[ERROR] Input file not found")
        exit(0)
        
    if no_split:
        if os.path.exists(no_split):
            scvol = modal.lookup("shadowclone")
            nosplit_file = open(no_split, 'rb')
            file_name = os.path.basename(no_split)
            scvol.write_file("data/"+file_name, nosplit_file)
            printerr("[INFO] Raw file uploaded successfully")
        else:
            printerr("[ERROR] File not found:"+ no_split)
            exit(0)
    
    # Generate a random alphanumeric string as scan_id
    num_letters = 5
    scan_id = ''.join(random.choices(string.ascii_letters + string.digits, k=num_letters))
    
    with stub.run():
        for outputs in execute_command.map(lines, 
                                           kwargs={"command":command, 
                                                   "nosplit": "/root/shadowclone/data/"+file_name if no_split else None,
                                                   "scan_id": scan_id}, 
                                           order_outputs=False):
            try:
                with open(output_file,'a') as outfile:
                    outfile.write(outputs)
            except:
                pass
            
    printerr("[INFO] Scan ID:" + scan_id)        

if __name__=="__main__":
    shadowclone()