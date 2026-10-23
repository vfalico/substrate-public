#!/usr/bin/env python3
"""Run native owning-compute microVM qualification with exact daemon ownership."""
import os,sys,pathlib,subprocess,time,json,shutil,hashlib,struct,base64
R=pathlib.Path(sys.argv[1]);out=R/'evidence'/sys.argv[2];out.mkdir(mode=0o700,exist_ok=False)
run=pathlib.Path('/run')/('poc-mv-'+str(os.getpid()));run.mkdir(mode=0o700)
pins=pathlib.Path('/sys/fs/bpf')/run.name;pins.mkdir()
shutil.copy2(R/'evidence/native-tool-harnessnode',out/'guest-probe')
raw=json.dumps(dict(version='agentsuite.policy/v2',network=dict(egressAllow=[dict(address='169.254.17.1',port=28292,protocol='TCP')]),requiredCapabilities=['network/egress-allow/v1']),sort_keys=True,separators=(',',':')).encode()
req=dict(format='agentsuite.policy/v2',bytes=base64.b64encode(raw).decode(),digest='sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(raw))+raw).hexdigest(),capabilities=['network/egress-allow/v1'])
(out/'requirement.json').write_text(json.dumps(req))
empty=json.dumps(dict(version='agentsuite.policy/v2',network=dict(egressAllow=[]),requiredCapabilities=['network/egress-allow/v1']),sort_keys=True,separators=(',',':')).encode()
empty_req=dict(format='agentsuite.policy/v2',bytes=base64.b64encode(empty).decode(),digest='sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(empty))+empty).hexdigest(),capabilities=['network/egress-allow/v1'])
(out/'empty-requirement.json').write_text(json.dumps(empty_req))

(run/'provider.json').write_text(json.dumps(dict(socket=str(run/'provider.sock'),state=str(out/'store.db'),pins=str(pins),object=str(R/'evidence/network.bpf.o'))))
(run/'runtime.json').write_text(json.dumps(dict(Socket=str(run/'provider.sock'),StateRoot=str(out/'runtime'))))
for p in run.glob('*.json'):p.chmod(0o600)
env=dict(os.environ,EXECUTION_TASK_ROOT=str(R),PYTHONPATH=str(R/'sources/guardd/src'),PYTHONUNBUFFERED='1')
daemon=None
echo=None
try:
 echo=subprocess.Popen(['/usr/bin/python3',str(pathlib.Path(__file__).with_name('microvm_dns_echo.py')),str(out/'dns-upstream.log')],stdout=subprocess.PIPE,text=True)
 port=echo.stdout.readline().strip()
 if not port.isdigit():raise RuntimeError('DNS upstream readiness')
 env.update(EXECUTION_MICROVM_DNS_UPSTREAM='127.0.0.1:'+port,EXECUTION_MICROVM_DNS_LOG=str(out/'dns-upstream.log'))
 with (out/'provider.log').open('w') as log:
  daemon=subprocess.Popen([str(R/'venv/bin/python'),'-m','agentsuite_guardd.cli','--config',str(run/'provider.json'),'serve-enforcement'],stdout=log,stderr=subprocess.STDOUT,env=env)
  deadline=time.monotonic()+15
  while not (run/'provider.sock').exists():
   if daemon.poll() is not None:raise RuntimeError('provider exited')
   if time.monotonic()>deadline:raise TimeoutError('provider readiness')
   time.sleep(.1)
  env.update(SUBSTRATE_EXECUTION_ENFORCER_CONFIG=str(run/'runtime.json'),EXECUTION_SESSIONS_CLIENT=str(R/'evidence/native-sessions-client'),EXECUTION_MICROVM_ROOT=str(out),EXECUTION_MICROVM_EMPTY_REQUIREMENT=str(out/'empty-requirement.json'),EXECUTION_MICROVM_REQUIREMENT=str(out/'requirement.json'))
  with (out/'compute.log').open('w') as output:
   compute=subprocess.Popen([str(R/'evidence/microvm-sessions-tools.test'),'-test.v','-test.run=^TestNativeMicroVMSessionsTools$','-test.timeout=200s'],stdout=output,stderr=subprocess.STDOUT,env=env)
   deadline=time.monotonic()+210
   try:
    while compute.poll() is None:
     if (out/'restart-request').exists() and not (out/'restart-ready').exists():
      old_pid=daemon.pid
      daemon.terminate();daemon.wait(timeout=10)
      if daemon.returncode!=0:raise RuntimeError('old Guardd failed controlled exit')
      daemon=subprocess.Popen([str(R/'venv/bin/python'),'-m','agentsuite_guardd.cli','--config',str(run/'provider.json'),'serve-enforcement'],stdout=log,stderr=subprocess.STDOUT,env=env)
      ready_deadline=time.monotonic()+10
      # A fresh connection must reach the new accepting listener; mere leftover
      # socket pathname presence cannot establish process readiness.
      import socket
      while True:
       if daemon.poll() is not None:raise RuntimeError('restarted Guardd exited')
       try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as probe:probe.connect(str(run/'provider.sock'))
        break
       except OSError:
        if time.monotonic()>ready_deadline:raise TimeoutError('restart readiness')
        time.sleep(.05)
      (out/'restart-ready').write_text(json.dumps(dict(old_pid=old_pid,new_pid=daemon.pid)))
      print('REAL_GUARDD_RESTART',old_pid,daemon.pid,flush=True)
     if time.monotonic()>deadline:raise TimeoutError('native qualification deadline')
     time.sleep(.1)
    result=compute
   finally:
    if compute.poll() is None:
     compute.terminate()
     try:compute.wait(timeout=10)
     except subprocess.TimeoutExpired:compute.kill();compute.wait(timeout=5)
  print('COMPUTE_EXIT',result.returncode,flush=True)
  print((out/'compute.log').read_text()[-10000:],flush=True)
  if result.returncode:raise RuntimeError('native microVM qualification failed; inspect exact residues')
finally:
 if echo is not None and echo.poll() is None:
  echo.terminate();echo.wait(timeout=5)
 if daemon is not None and daemon.poll() is None:
  daemon.terminate()
  try:daemon.wait(timeout=10)
  except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=5)
 print('DAEMON_EXIT',None if daemon is None else daemon.returncode,flush=True)
 print('PINS_REMAIN',[p.name for p in pins.iterdir()],flush=True)
 if not list(pins.iterdir()):pins.rmdir()
 shutil.copy2(run/'provider.json',out/'provider-config.json');shutil.copy2(run/'runtime.json',out/'runtime-config.json')
 print('CONFIG_RETAINED',run,flush=True)
