"""Prepare the pinned Universal candidate for a live code-authenticated worker.
Build/sign only: never installs or executes GOST. Source bytes stay unchanged.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys

UNSIGNED_BYTES=70287474
UNSIGNED_SHA256='bfa76e74d54de90e7facd54b9ea86555cf407c004db823af10e3834f088c3992'
IDENTIFIER='kz.documentolog.proxypilot.bridge.gost'
SIGNED_BYTES=70437264
SIGNED_SHA256='d8951461a89fc6a4685d9440095be8b17aabda9d9ed7d4c4b237c056692b0e02'
SIGNED_CDHASH={'arm64':'055936ed28ac6b392602daa670a98f3b09ec8117',
               'x86_64':'a29dc60b0d6ffb7de83e24cbaa91528c6aef7fb0'}


def identity(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_uid,info.st_mode,
            info.st_nlink,info.st_mtime_ns,info.st_ctime_ns)


def run(arguments):
    result=subprocess.run(arguments,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    if result.returncode:
        stage='verify' if '--verify' in arguments else 'inspect' if '--display' in arguments else 'sign'
        print(json.dumps({'event':'signingToolRefused','stage':stage,'exit':result.returncode}),file=sys.stderr)
        raise ValueError('signingRefused')
    return result


def source_chunks(descriptor):
    remaining=UNSIGNED_BYTES
    while remaining:
        data=os.read(descriptor,min(1024*1024,remaining))
        if not data:raise ValueError('sourceChanged')
        remaining-=len(data);yield data
    if os.read(descriptor,1):raise ValueError('sourceChanged')


def prepare(source,destination):
    if sys.platform!='darwin' or os.getuid()!=os.geteuid() or os.getuid()==0:
        raise ValueError('ordinaryMacOSBuilderRequired')
    recipe=Path(__file__).read_bytes()
    source=Path(source);destination=Path(destination)
    if not source.is_absolute() or not destination.is_absolute():raise ValueError('absolutePathsRequired')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
                and before.st_nlink==1 and before.st_size==UNSIGNED_BYTES):raise ValueError('sourceRefused')
        # Validate BEFORE creating/signing any destination.
        digest=hashlib.sha256()
        for data in source_chunks(fd):digest.update(data)
        if digest.hexdigest()!=UNSIGNED_SHA256:raise ValueError('sourceRefused')
        if identity(os.lstat(source))!=identity(before) or identity(os.fstat(fd))!=identity(before):raise ValueError('sourceChanged')
        destination.mkdir(mode=0o700)
        directory=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(directory)
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('destinationRefused')
            target=destination/'gost'
            output=os.open('gost',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o700,dir_fd=directory)
            try:
                os.lseek(fd,0,os.SEEK_SET);copied=hashlib.sha256()
                for data in source_chunks(fd):
                    copied.update(data);offset=0
                    while offset<len(data):
                        size=os.write(output,data[offset:])
                        if size<=0:raise ValueError('writeRefused')
                        offset+=size
                os.fsync(output)
            finally:os.close(output)
            if copied.hexdigest()!=UNSIGNED_SHA256:raise ValueError('sourceChanged')
            if identity(os.fstat(fd))!=identity(before) or identity(os.lstat(source))!=identity(before):raise ValueError('sourceChanged')
            run(['/usr/bin/codesign','--force','--sign','-','--identifier',IDENTIFIER,
                 '--options','runtime,hard,kill','--runtime-version','12.0.0',
                 '--timestamp=none','--digest-algorithm=sha256',str(target)])
            run(['/usr/bin/codesign','--verify','--strict','--all-architectures',str(target)])
            signed=target.read_bytes();sha=hashlib.sha256(signed).hexdigest()
            if len(signed)!=SIGNED_BYTES or sha!=SIGNED_SHA256:
                # Public artifact metadata only: never executable bytes, paths,
                # credentials or raw tool output. The fixed pin still rejects it.
                print(json.dumps({'event':'signedPinMismatch','bytes':len(signed),'sha256':sha}),file=sys.stderr)
                raise ValueError('signedPinMismatch')
            hashes={}
            for arch in ('arm64','x86_64'):
                display=run(['/usr/bin/codesign','--display','--verbose=4','--arch',arch,str(target)])
                values=re.findall(rb'^CDHash=([a-f0-9]{40})$',display.stderr,re.M)
                if len(values)!=1:raise ValueError('codeIdentityRefused')
                hashes[arch]=values[0].decode()
                if hashes[arch]!=SIGNED_CDHASH[arch]:raise ValueError('codeIdentityRefused')
            final=os.open('gost',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            try:
                info=os.fstat(final)
                if not (stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                        and info.st_size==SIGNED_BYTES and stat.S_IMODE(info.st_mode)==0o700):raise ValueError('signedFileRefused')
                os.fsync(final)
            finally:os.close(final)
            if recipe!=Path(__file__).read_bytes():raise ValueError('recipeChanged')
            if identity(os.fstat(fd))!=identity(before) or identity(os.lstat(source))!=identity(before):raise ValueError('sourceChanged')
            proof={'schema':1,'unsignedSHA256':UNSIGNED_SHA256,'identifier':IDENTIFIER,
                   'bytes':len(signed),'sha256':sha,'cdhash':hashes,
                   'recipeSHA256':hashlib.sha256(recipe).hexdigest(),
                   'scope':'sign/verify only; no worker execution or installation'}
            record=os.open('verification.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            with os.fdopen(record,'w') as stream:
                json.dump(proof,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
            return proof
        finally:os.close(directory)
    finally:os.close(fd)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source');parser.add_argument('destination')
    arguments=parser.parse_args();os.umask(0o077)
    try:result=prepare(arguments.source,arguments.destination)
    except Exception as error:
        known={'ordinaryMacOSBuilderRequired','absolutePathsRequired','sourceRefused','sourceChanged',
               'destinationRefused','writeRefused','signingRefused','signedPinMismatch','codeIdentityRefused',
               'signedFileRefused','recipeChanged'}
        reason=str(error) if isinstance(error,ValueError) and str(error) in known else 'other'
        raise SystemExit('Signed bridge candidate preparation refused: '+reason)
    print(json.dumps(result))
