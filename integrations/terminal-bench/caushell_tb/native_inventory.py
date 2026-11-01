"""Optional operator-attested native identities; facts never confer permission.

The manifest is a deployment contract, not discovered model/tool data. Its author
must attest that the pinned image and file closure determine this implementation
and cannot load code through unlisted files or ambient loader controls. An empty
inventory is the default. No version command or task executable is run here.
"""
import json
from pathlib import Path, PurePosixPath
import re

LOADER_NAMES = ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH','LD_DEBUG','LD_DEBUG_OUTPUT',
                'LD_TRACE_LOADED_OBJECTS','LD_PROFILE','LD_PROFILE_OUTPUT',
                'LD_SHOW_AUXV','LD_VERBOSE','LD_WARN','LD_TRACE_PRELINKING',
                'LD_BIND_NOW','LD_BIND_NOT','LD_ASSUME_KERNEL','LD_ORIGIN_PATH',
                'LD_USE_LOAD_BIAS','LD_DYNAMIC_WEAK','LD_HWCAP_MASK',
                'LD_PREFER_MAP_32BIT_EXEC','LD_POINTER_GUARD','GCONV_PATH',
                'GLIBC_TUNABLES','DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH',
                'DYLD_FRAMEWORK_PATH','DYLD_FALLBACK_LIBRARY_PATH','DYLD_ROOT_PATH')


def validate(value, image_id):
    if (not isinstance(value,dict) or set(value)!={'schema','image_id','commands'}
            or type(value['schema']) is not int or value['schema']!=1 or value['image_id']!=image_id
            or not isinstance(image_id,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
            or not isinstance(value['commands'],dict) or len(value['commands'])>16):
        raise ValueError('Invalid native implementation deployment contract')
    total=0
    for name, row in value['commands'].items():
        if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',name)
                or not isinstance(row,dict) or set(row)!={'variant','executable','files','closed_runtime'}
                or row['closed_runtime'] is not True
                or not isinstance(row['variant'],str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',row['variant'])
                or not isinstance(row['files'],dict) or not 1<=len(row['files'])<=64
                or not isinstance(row['executable'],str) or row['executable'] not in row['files']):
            raise ValueError('Native implementation lacks a closed runtime attestation')
        for path,pin in row['files'].items():
            if (not isinstance(path,str) or len(path)>4096 or '\0' in path
                    or not path.startswith('/') or str(PurePosixPath(path))!=path
                    or '..' in PurePosixPath(path).parts
                    or not isinstance(pin,dict) or set(pin)!={'sha256','size'}
                    or not isinstance(pin['sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',pin['sha256'])
                    or type(pin['size']) is not int or not 0<=pin['size']<=16*1024*1024):
                raise ValueError('Invalid bounded native runtime file pin')
            total+=pin['size']
    if total>16*1024*1024:raise ValueError('Native runtime inventory exceeds budget')
    return value


def load(path, image_id):
    path=Path(path)
    if path.stat().st_size>65536:raise ValueError('Native manifest exceeds budget')
    return validate(json.loads(path.read_text()),image_id)


def verified_variants(inventory, frame, lookups, observe):
    """Require owning lookup, complete current namespace pins and loader facts."""
    env={v['name']:v['value'] for v in frame.get('environment',[])}
    if any(env.get(n,{}).get('status')!='absent'
           and env.get(n)!={'status':'present','value':''} for n in LOADER_NAMES):return {}
    found={}
    for name,row in inventory.get('commands',{}).items():
        if lookups.get(name)!={'kind':'file','path':row['executable']}:continue
        complete=True
        for path,pin in row['files'].items():
            value=observe(path)
            if not isinstance(value,dict) or not isinstance(value.get('content'),dict):
                complete=False;break
            content=value['content']
            identity=content.get('identity')
            if not isinstance(identity,dict):complete=False;break
            if (content.get('status')!='complete' or content.get('path')!=path
                    or content.get('source')!='current_process'
                    or content.get('byte_limit')!=33_554_432
                    or content.get('sha256')!=pin['sha256']
                    or content.get('bytes_observed')!=pin['size']
                    or identity.get('size')!=pin['size']
                    or (path==row['executable'] and value.get('executable') is not True)):
                complete=False;break
        if complete:found[name]=row['variant']
    return found
