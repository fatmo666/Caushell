import hashlib
import json
from pathlib import Path
import shutil
import stat


def save(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def manifest(root):
    root=Path(root)
    result={}
    for p in sorted(root.rglob('*')):
        m=p.lstat();name=str(p.relative_to(root))
        if stat.S_ISLNK(m.st_mode):result[name]=dict(kind='symlink',target=str(p.readlink()))
        elif stat.S_ISREG(m.st_mode):result[name]=dict(kind='file',sha256=sha(p),mode=stat.S_IMODE(m.st_mode))
        elif stat.S_ISDIR(m.st_mode):result[name]=dict(kind='directory',mode=stat.S_IMODE(m.st_mode))
        else:raise ValueError('Unsupported task source entry: '+name)
    return result


def prepare_task(source, destination, record):
    """No TOML/USER/artifact/timeout/test rewriting, including omitted defaults."""
    source,destination=Path(source).resolve(),Path(destination).absolute()
    before=manifest(source)
    if destination.exists():raise FileExistsError(destination)
    shutil.copytree(source,destination,symlinks=True)
    after=manifest(destination)
    if before!=after or before!=manifest(source):raise ValueError('Task source changed during preparation')
    save(record,dict(original=str(source),prepared=str(destination),byte_and_mode_identical=True,files=before,task_config_sha256=sha(source/'task.toml'),semantic_overrides={}))
    return destination


def overlay(assets, mount, image_id, owner):
    assets=Path(assets).resolve()
    if not assets.is_dir() or not mount.startswith('/tmp/.caushell-harness-'):
        raise ValueError('Private harness assets are required')
    if not image_id.startswith('sha256:') or len(image_id)!=71:raise ValueError('Immutable image ID required')
    return dict(services=dict(main=dict(image=image_id,labels={'org.caushell.rq3.faithful.owner':owner},volumes=[dict(type='bind',source=str(assets),target=mount,read_only=True,bind=dict(create_host_path=False))])),networks=dict(default=dict(labels={'org.caushell.rq3.faithful.owner':owner})))


def validate_overlay(value):
    main=value['services']['main']
    if set(main)!={'image','labels','volumes'}:raise ValueError('Overlay changes task runtime semantics')
    if set(value)!={'services','networks'} or set(value['services'])!={'main'} or set(value['networks'])!={'default'} or set(value['networks']['default'])!={'labels'}:raise ValueError('Unexpected compose surface')
    if len(main['volumes'])!=1:raise ValueError('Only one immutable harness mount allowed')
    for v in main['volumes']:
        if not v.get('read_only') or not v['target'].startswith('/tmp/.caushell-harness-'):raise ValueError('Unprotected harness mount')
    return value


def task_users(config, image):
    """None means inherit the image USER; it never means substitute bench/root."""
    return dict(image_user=image.get('Config',{}).get('User',''),agent_user=config.get('agent',{}).get('user'),verifier_user=config.get('verifier',{}).get('user'),verifier_environment_mode=config.get('verifier',{}).get('environment_mode'))


def validate_container(info, expected_image, assets, mount, evidence):
    if info['Image']!=expected_image:raise ValueError('Container image identity changed')
    host=info['HostConfig']
    if host.get('Privileged') or {'SYS_PTRACE','SYS_ADMIN','ALL'} & {x.removeprefix('CAP_') for x in host.get('CapAdd') or []}:
        raise ValueError('Task privileges cannot protect the observer; refusing rather than dropping task capabilities')
    found=False
    evidence=Path(evidence).resolve();assets=Path(assets).resolve()
    for m in info.get('Mounts',[]):
        source=Path(m['Source']).resolve()
        if source==evidence or source in evidence.parents or evidence in source.parents:raise ValueError('Controller evidence exposed to task')
        if m['Destination']==mount:
            if source!=assets or m['RW']:raise ValueError('Harness assets are not immutable')
            found=True
        if m['Destination'].endswith('docker.sock'):raise ValueError('Docker socket exposed to task')
    if not found:raise ValueError('Missing immutable harness mount')


def verify_plan(plan):
    if plan.get('native_inventory_path'):
        from .native_inventory import load
        if sha(plan['native_inventory_path'])!=plan['native_inventory_sha256']:raise ValueError('Native implementation contract changed')
        load(plan['native_inventory_path'],plan['image_id'])
    for name,digest in plan.get('execution_frame_files',{}).items():
        if sha(Path(plan['execution_frame_root'])/name)!=digest:raise ValueError('Execution-frame collector changed')
    for field in ['runtime_files','integration_files']:
        root=Path(plan['runtime_root'] if field=='runtime_files' else plan['integration_root'])
        for name,digest in plan[field].items():
            if sha(root/name)!=digest:raise ValueError('Pinned runner input changed: '+name)
    if manifest(plan['task'])!=plan['task_manifest']:raise ValueError('Upstream task input changed')
    if sha(plan['compose'])!=plan['compose_sha256']:raise ValueError('Compose overlay changed')
    validate_overlay(json.loads(Path(plan['compose']).read_text()))
    for key in ['host_guard','guard_config']:
        if sha(plan[key])!=plan[key+'_sha256']:raise ValueError('Trusted controller input changed: '+key)
    if manifest(plan['assets'])!=plan['asset_manifest']:raise ValueError('Immutable asset permissions/contents changed')
    if {str(p.relative_to(plan['assets'])):sha(p) for p in Path(plan['assets']).rglob('*') if p.is_file()}!=plan['asset_sha256']:
        raise ValueError('Immutable harness assets changed')


def admit_model(plan,plan_path):
    if plan['mode']!='local':return
    if not plan.get('local_model_launch_authorized'):raise ValueError('Model use not authorized in this plan')
    bootstrap=Path(plan_path).parent/'preflight/acceptance.json'
    if not bootstrap.exists():raise ValueError('Successful isolated verifier preflight required before inference')
    admission=json.loads(bootstrap.read_text())
    if not admission['verified'] or admission['plan_sha256']!=sha(plan_path):raise ValueError('Verifier preflight is stale or failed')


def validate_native_client(assets,image,layout):
    # Claude helpers reexec /proc/self/exe; ld.so is not a client executable.
    if layout['claude']!=['{assets}/claude']:raise ValueError('Claude must launch directly, using matching image architecture assets')
    with (Path(assets)/'claude').open('rb') as stream:header=stream.read(20)
    machine=int.from_bytes(header[18:20],'little') if header[:6]==b'\x7fELF\x02\x01' else None
    expected={'amd64':62,'arm64':183}.get(image.get('Architecture'))
    if machine!=expected or expected is None:raise ValueError('Native client architecture does not match original image; supply matching assets, do not patch the task environment')
