"""Local process drill. Inputs: verified-release archive, development executable.
Run with Python 3.11+ and OpenSSL. Only disposable synthetic configurations are used.
"""
import asyncio as aio
import contextlib
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile

HOST = '127.0.0.1'
BASE_REV = '4ff413039a39aaa1a157080ca233e64dfe87bcb1'
ARCHIVES = {
    'aarch64-apple-darwin': 'e6e109978168dd9b89f9d5a5db9eb75cc31da0e9fcc700f1638c3b0735ca6a71',
    'x86_64-unknown-linux-gnu': '9fbe1664cc4b4f7ff321ff66149a525e4a2f142b36e1617b53948d28786c5bf2',
}

def check(condition, label):
    if not condition:
        raise RuntimeError(label)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(args, cwd):
    proc = subprocess.run(args, cwd=cwd, timeout=20, capture_output=True)
    check(proc.returncode == 0, f'failed {Path(args[0]).name} {args[1]}')
    return proc.stdout

def baseline(archive, target, dest):
    check(digest(archive) == ARCHIVES[target], 'published archive digest')
    with tarfile.open(archive) as data:
        def read(name):
            return data.extractfile('maverick-pilot/' + name).read()
        source = read('SOURCE.txt').decode().splitlines()
        check(f'git_revision: {BASE_REV}' in source and f'target: {target}' in source
              and 'version: 1.2.0' in source and 'source_state: clean' in source, 'source identity')
        dest.write_bytes(read('maverick'))
        check(f'{digest(dest)}  maverick' in read('SHA256SUMS').decode().splitlines(), 'binary digest')
        dest.chmod(0o700)

def cert(directory, name):
    ca = name + '-ca'
    command(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
             '-nodes','-keyout',ca+'.key','-out',ca+'.pem','-days','2','-subj','/CN='+ca,
             '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],directory)
    command(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
             '-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=localhost'],directory)
    ext = directory / 'leaf.ext'
    ext.write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n')
    command(['openssl','x509','-req','-in',name+'.csr','-CA',ca+'.pem','-CAkey',ca+'.key',
             '-CAcreateserial','-days','2','-extfile','leaf.ext','-out',name+'.pem'],directory)

def changed(text, old, new):
    check(text.count(old) == 1, 'unexpected configuration template')
    return text.replace(old, new, 1)

def free_port():
    with socket.socket() as sock:
        sock.bind((HOST,0))
        return sock.getsockname()[1]

@contextlib.asynccontextmanager
async def cli(slot, role, ready, mode):
    proc = await aio.create_subprocess_exec(slot/'maverick', role, '-c', role+'.yaml', cwd=slot,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=dict(os.environ, RUST_LOG='info,maverick_client::connection_manager=debug'))
    observed = {'tcp': [], 'h2_created': []}
    async def watch():
        async for line in proc.stdout:
            for carrier in ('H2','H3'):
                if ('automatic selection chose '+carrier+' for new TCP connection').encode() in line:
                    observed['tcp'].append(carrier)
            if b'Maverick H2 pool shutdown summary:' in line:
                count = re.search(rb'\bconnections_created=(\d+)\b',line)
                if count:
                    observed['h2_created'].append(int(count[1]))
    watcher = None
    try:
        async with aio.timeout(8):
            while line := await proc.stdout.readline():
                if ready.encode() in line:
                    endpoint = re.search(rb'127\.0\.0\.1:(\d+)',line)
                    check(endpoint is not None, 'loopback readiness')
                    port = int(endpoint[1])
                    break
            else:
                raise RuntimeError(f'{role} readiness ({mode})')
        watcher = aio.create_task(watch())
        yield port, observed
    finally:
        if proc.returncode is None:
            proc.send_signal(signal.SIGINT if role=='client' else signal.SIGTERM)
            try:
                await aio.wait_for(proc.wait(),8)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                raise RuntimeError(f'{role} stop deadline')
        if watcher:
            await watcher
        check(proc.returncode == 0, f'{role} did not stop normally')

class Edge:
    """Terminate outer TLS locally and stream its H2 bytes in a separately verified TLS connection."""
    def __init__(self, material, origin_port):
        self.material, self.origin_port = material, origin_port
        self.tasks = set()
        self.forwarded = 0

    async def start(self):
        inbound = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        inbound.minimum_version = ssl.TLSVersion.TLSv1_3
        inbound.set_alpn_protocols(['h2'])
        inbound.load_cert_chain(self.material/'edge.pem',self.material/'edge.key')
        self.upstream = ssl.create_default_context(cafile=str(self.material/'origin-ca.pem'))
        self.upstream.minimum_version = ssl.TLSVersion.TLSv1_3
        self.upstream.set_alpn_protocols(['h2'])
        self.server = await aio.start_server(self.forward, HOST, 0, ssl=inbound)
        return self.server.sockets[0].getsockname()[1]

    async def forward(self, reader, writer):
        self.tasks.add(aio.current_task())
        peer = None
        try:
            origin, peer = await aio.open_connection(HOST,self.origin_port,ssl=self.upstream,server_hostname='localhost')
            check(all(w.get_extra_info('ssl_object').selected_alpn_protocol()=='h2' for w in (writer,peer)), 'H2 ALPN')
            async def copy(r,w):
                while buf := await r.read(65536):
                    w.write(buf)
                    await w.drain()
                    self.forwarded += len(buf)
            a,b = [aio.create_task(copy(*pair)) for pair in [(reader,peer),(origin,writer)]]
            try:
                await aio.wait((a,b),return_when=aio.FIRST_COMPLETED)
            finally:
                for task in (a,b):
                    task.cancel()
                await aio.gather(a,b,return_exceptions=True)
        finally:
            writer.close()
            if peer:
                peer.close()
            self.tasks.discard(aio.current_task())

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await aio.gather(*tasks,return_exceptions=True)

async def socks(port, cmd, target):
    r,w = await aio.open_connection(HOST,port)
    try:
        w.write(b'\x05\x01\x00')
        await w.drain()
        check(await r.readexactly(2)==b'\x05\x00','SOCKS greeting')
        w.write(bytes([5,cmd,0,1])+socket.inet_aton(HOST if cmd==1 else '0.0.0.0')+struct.pack('!H',target))
        await w.drain()
        reply=await r.readexactly(10)
        check(reply[:4]==bytes([5,0,0,1]),'SOCKS admission')
        return r,w,(socket.inet_ntoa(reply[4:8]),struct.unpack('!H',reply[8:])[0])
    except BaseException:
        w.close()
        raise

async def transfer(proxy):
    loop=aio.get_running_loop()
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp, socket.socket(type=socket.SOCK_DGRAM) as app:
        for sock in (tcp,udp,app):
            sock.bind((HOST,0))
            sock.setblocking(False)
        tcp.listen()
        upload,download=os.urandom(8193),os.urandom(6145)
        r,w,_ = await socks(proxy,1,tcp.getsockname()[1])
        peer,_ = await loop.sock_accept(tcp)
        try:
            with peer:
                pr,pw=await aio.open_connection(sock=peer)
                w.write(upload)
                await w.drain()
                w.write_eof()
                check(await pr.read()==upload, 'TCP target bytes and EOF')
                pw.write(download)
                await pw.drain()
                pw.write_eof()
                check(await r.read()==download, 'TCP client bytes and EOF')
                pw.close()
                await pw.wait_closed()
        finally:
            w.close()
            await w.wait_closed()
        _,control,relay=await socks(proxy,3,0)
        try:
            check(relay[0] == HOST and relay[1] != 0,'SOCKS UDP loopback')
            header=b'\x00\x00\x00\x01'+socket.inet_aton(HOST)+struct.pack('!H',udp.getsockname()[1])
            first_peer=None
            for length in [71,113]:
                payload=os.urandom(length)
                await loop.sock_sendto(app,header+payload,relay)
                data,source=await loop.sock_recvfrom(udp,65535)
                check(data==payload and source[0]==HOST,'UDP target bytes')
                if first_peer is None:
                    first_peer=source
                check(source==first_peer,'UDP source port continuity')
                for reply in (os.urandom(79),os.urandom(37)):
                    await loop.sock_sendto(udp,reply,source)
                    data,from_addr=await loop.sock_recvfrom(app,65535)
                    check(from_addr==relay and data==header+reply,'UDP independent reply')
        finally:
            control.close()
            await control.wait_closed()

async def route(root, old, new, name, options):
    origin_port = free_port()
    protected = name == 'protected-h2'
    edge = Edge(root,origin_port) if protected else None
    destination = await edge.start() if edge else origin_port
    route_dir=root/name
    route_dir.mkdir()
    generated=route_dir/'generated'
    generated.mkdir()
    if protected:
        options=['--relay','--origin-name','localhost','--origin-cert',root/'origin.pem','--origin-ca',root/'origin-ca.pem']
    command([old,'gen-config',*options],generated)
    client=(generated/'client.generated.yaml').read_text()
    server=(generated/'server.generated.yaml').read_text()
    client=changed(client,'127.0.0.1:1080','127.0.0.1:0')
    client=changed(client,'example.com:443',f'{HOST}:{destination}')
    client=changed(client,'server_name: "example.com"','server_name: "localhost"')
    client=changed(client,'ca_cert: null',f'ca_cert: "{root}/{"edge" if protected else "origin"}-ca.pem"')
    server=changed(server,'0.0.0.0:443',f'{HOST}:{origin_port}')
    server=changed(server,'./certs/fullchain.pem',str(root/'origin.pem'))
    server=changed(server,'./certs/privkey.pem',str(root/'origin.key'))
    server=changed(server,'allow_loopback: false','allow_loopback: true')
    server=changed(server,'1.1.1.1:53',f'{HOST}:{free_port()}')
    if name=='auto-h2-only':
        server=changed(server,'dual_h2_h3: true','dual_h2_h3: false')
    marker = ('Maverick H2/H3 server listening' if name in ('auto-reliable','auto-native')
              else 'Maverick H3 server listening' if name=='direct-h3'
              else 'Maverick server listening')
    for role,data in [('client',client),('server',server)]:
        slot=route_dir/role
        slot.mkdir()
        (slot/'public').mkdir()
        shutil.copy2(old,slot/'maverick')
        (slot/(role+'.yaml')).write_text(data)
        shutil.copytree(slot, route_dir/('backup-'+role))
    new_config={'client':changed(client,'max_concurrent_flows: 256','max_concurrent_flows: 64'),
                'server':changed(server,'max_concurrent_flows_per_user: 128','max_concurrent_flows_per_user: 64')}
    try:
        for phase,client_new,server_new in [('baseline',False,False),('new-client',True,False),('new-server',False,True),
                                           ('upgraded',True,True),('restored',False,False)]:
            for role,is_new in [('client',client_new),('server',server_new)]:
                slot,backup=route_dir/role,route_dir/('backup-'+role)
                binary,config=slot/'maverick',slot/(role+'.yaml')
                prior_config=backup/config.name
                check(digest(backup/'maverick') == digest(old),'backup binary changed')
                check(prior_config.read_text() == (client if role=='client' else server),'backup config changed')
                if phase!='baseline':
                    incoming=slot/'maverick.incoming'
                    shutil.copy2(new if is_new else backup/'maverick',incoming)
                    incoming.replace(binary)
                    if is_new:
                        config.write_text(new_config[role])
                    else:
                        shutil.copy2(prior_config,config)
                check(digest(binary)==digest(new if is_new else old),'active binary identity')
                check(config.read_text()==(new_config[role] if is_new else prior_config.read_text()),'active config identity')
                check(digest(config)!=digest(prior_config) if is_new else digest(config)==digest(prior_config), 'config change/restore')
                check(config.stat().st_mode & 0o077 == 0,'config permissions')
                check(command([binary,'check-config','--kind',role,'-c',config],slot) == f'{role} config OK\n'.encode(),'config preflight')
            before=edge.forwarded if edge else 0
            async with cli(route_dir/'server','server',marker,name) as (bound,_):
                check(bound==origin_port,'same server endpoint')
                async with cli(route_dir/'client','client','Maverick SOCKS5 client listening',name) as (proxy,observed):
                    async with aio.timeout(15):
                        await transfer(proxy)
                if name.startswith('auto-'):
                    expected='H2' if name=='auto-h2-only' else 'H3'
                    check(observed['tcp']==[expected],'actual TCP selection')
                if name=='auto-reliable':
                    check(observed['h2_created']==[0],'unexpected reliable H2 connection on healthy auto route')
            if edge:
                check(edge.forwarded>before,'protected intermediary carried this phase')
            print(f'{name} {phase} PASS',flush=True)
    finally:
        if edge:
            await edge.close()

async def main():
    os.umask(0o077)
    archive,development,target=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    with tempfile.TemporaryDirectory(prefix='maverick-stable-interop-') as directory:
        root=Path(directory)
        old=root/'maverick'
        baseline(archive,target,old)
        check(digest(old)!=digest(development),'distinct input binaries')
        for binary in (old,development):
            check(command([binary,'version'],root).splitlines()[0]==b'maverick 1.2.0','expected unbumped package version')
        print(f'published binary SHA256 {digest(old)}\ndevelopment binary SHA256 {digest(development)}',flush=True)
        for kind in ['origin','edge']:
            cert(root,kind)
        routes=dict([('direct-h2',['--h2']),('direct-h3',['--quiche-h3']),('auto-reliable',[]),
                     ('auto-native',['--udp-policy','native_required']),('auto-h2-only',[]),('protected-h2',[])])
        for name in sys.argv[4:] or routes:
            await route(root,old,development,name,routes[name])

if __name__=='__main__':
    aio.run(main())
