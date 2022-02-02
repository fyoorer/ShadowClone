import datetime
from lithops import FunctionExecutor
from lithops import Storage
import argparse
import os.path
import delegator
import uuid
import sys
import config
import tempfile
from multiprocessing.pool import ThreadPool


def splitfile(infile, SPLIT_NUM):
    # from https://stackoverflow.com/questions/16289859/splitting-large-text-file-into-smaller-text-files-by-line-numbers-using-python
    lines_per_file = int(SPLIT_NUM)

    smallfile = None
    chunks = []
    with open(infile) as bigfile:
        tempdir = tempfile.gettempdir()
        for lineno, line in enumerate(bigfile):
            if lineno % lines_per_file == 0:
                if smallfile:
                    smallfile.close()
                # small_filename = '/tmp/small_file_{}.txt'.format(lineno + lines_per_file)
                small_filename = os.path.join(tempdir, 'small_file_{}.txt'.format(lineno + lines_per_file))
                chunks.append(small_filename)
                smallfile = open(small_filename, "w")
            smallfile.write(line)
        if smallfile:
            smallfile.close()
    return chunks


def upload_to_bucket(chunk):
    bucket_name = config.STORAGE_BUCKET
    f = open(chunk,'r')
    contents = f.read()
    upload_key = str(uuid.uuid4())
    try:
        storage.put_object(bucket=bucket_name, key=upload_key, body=contents)
    except Exception as e:
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [ERROR] Error occured while accessing the storage bucket. Did you update the config.py file?")
        # exit()
        pass
    return bucket_name+'/'+upload_key


def delete_bucket_files(fileslist):
    sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [INFO] Cleaning up\n")
    # storage = Storage()
    keys = []
    bucket_name = fileslist[0].split('/')[0]
    for f in fileslist:
        keys.append(f.split('/')[1])
    
    # delete all at once
    try:
        storage.delete_objects(bucket=bucket_name, key_list=keys)
    except Exception as e:
        raise e
    return


def execute_command(obj, command):
    data = obj.data_stream.read()

    with open('/tmp/infile','w') as infile:
        for line in data.splitlines():
            infile.write(line.decode("UTF-8")+'\n')

    cmd = command.replace('{INPUT}','/tmp/infile')
    cmd = cmd.replace('{OUTPUT}','/tmp/outfile')

    try:
        results = delegator.run(cmd, timeout=-1)
    except:
        print("Error in running the command:"+ command)
    return results.out


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', dest='input', required=True, help="File that you want to distribute")
    parser.add_argument('-s', '--split', dest='splitnum', required=False, help="Number of lines per chunk of file")
    parser.add_argument('-o', '--output', dest='output', required=False, help="Write output to a file")
    parser.add_argument('-c', '--command', dest='command', required=True, help="Command to execute") 
    args = parser.parse_args()

    runtime = config.LITHOPS_RUNTIME
    bucket_name = config.STORAGE_BUCKET
    infile = args.input
    command = args.command
    storage = Storage()

    if args.splitnum:
        try:
            SPLIT_NUM = int(args.splitnum)
        except:
            SPLIT_NUM = 1000
    else:
        SPLIT_NUM = 1000

    if os.path.exists(infile):        
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [INFO] Splitting input file into chunks of "+ str(SPLIT_NUM) +" lines\n")
        chunks = splitfile(infile, SPLIT_NUM)
        pool = ThreadPool(processes=100) # 100 upload threads
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [INFO] Uploading chunks to storage\n")
        filekeys = pool.map(upload_to_bucket, chunks)
        # print(filekeys)
        object_chunksize = 1*1024**2
        try:
            fexec = FunctionExecutor(runtime=runtime) # change runtime memory if reuired
            fexec.map(execute_command,filekeys, obj_chunk_size=object_chunksize, extra_args={command})
            output = fexec.get_result()
        except:
            sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [ERROR] Could not execute the runtime.\n")
            exit()
    else:
        sys.stderr.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " [ERROR] Input file not found")
        exit()

    # print(output)
    for line in output:
        if len(line):
            if args.output:
                try:
                    with open(args.output,'a') as outfile:
                        outfile.write(line)
                except:
                    pass
            print(line)

    # delete input files from bucket
    delete_bucket_files(filekeys)


