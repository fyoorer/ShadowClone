import sys
from lithops import FunctionExecutor, storage
from lithops import Storage
import argparse
import os.path
import subprocess
import config
import datetime
import delegator


def dns_bruteforce(obj, domain):
    data = obj.data_stream.read()
    wf = open('/tmp/wordlist','w')

    # write wordlist to file
    for line in data.splitlines():
        wf.write(line.decode("UTF-8")+'\n')

    # puredns command
    cmd = '/go/bin/puredns bruteforce /tmp/wordlist ' + domain + ' --resolvers /function/resolvers.txt -t 200'

    try:
        results = delegator.run(cmd, timeout=-1)
    except:
        print("Error in running the command:"+ cmd)
    return results.out


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', dest='domain', required=True)
    parser.add_argument('-w', '--wordlist', dest='wordlist', required=True, help="Path to local wordlist file")
    parser.add_argument('-o', '--output', dest='output', required=False, help="Write output to a file") 
    # parser.add_argument('-b','--bucket',dest='bucket', required=True)
    # parser.add_argument('-k','--key',dest='key', required=False, help='Name of the wordlist stored in the bucket')

    args = parser.parse_args()


    BUCKET_NAME = config.STORAGE_BUCKET  
    wordlist_file =  args.wordlist 
    obj_key = wordlist_file.split('/')[-1]  # TODO: add handler for Windows
    object_chunksize = 1*1024**2    # 1 MB - lowest possible chunk size

    storage = Storage()
    bucket_files = storage.list_keys(bucket=BUCKET_NAME)

    if obj_key in bucket_files:
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [INFO] File with same name already exists in the bucket, skipping upload\n")
    else:
        if os.path.exists(wordlist_file):
            f = open(wordlist_file,'r')
            contents = f.read()
            try:
                storage.put_object(bucket=BUCKET_NAME, key=obj_key, body=contents)
            except:
                sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [ERROR] Error occured while accessing the storage bucket. Did you update the config.py file?\n")
                exit()
        else:
            sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]+" [ERROR] Wordlist file does not exist\n")
            exit(2)

    iterdata = [BUCKET_NAME+'/'+obj_key]
    # print(iterdata)
    domain = args.domain

    try:
        fexec = FunctionExecutor(runtime=config.LITHOPS_RUNTIME,runtime_memory=256) # change runtime
        fexec.map(dns_bruteforce,iterdata, obj_chunk_size=object_chunksize, extra_args={domain})
        output = fexec.get_result()
    except:
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [ERROR] Could not execute the runtime.\n")
        exit()

    for line in output:
        if len(line):
            if args.output:
                try:
                    with open(args.output,'a') as outfile:
                        outfile.write(line)
                except:
                    pass
            print(line)
