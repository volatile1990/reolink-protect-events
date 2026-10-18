import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('controls_worker',Path(__file__).resolve().parents[1]/'services/controls/worker.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)

ID='a'*24
BRIDGES={ID:{'cameraId':ID,'host':'192.168.30.210','username':'fixture','password':'fixture'}}

class Reply(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

class WorkerTests(unittest.TestCase):
    def job(self,**kwargs):
        return dict({'cameraId':ID,'host':'192.168.30.210','method':'GET','resource':'state','body':None,'queryType':None},**kwargs)

    def test_rejects_host_substitution_and_unscoped_identity(self):
        for job in (self.job(host='127.0.0.1'),self.job(cameraId='b'*24),self.job(resource='../config'),self.job(resource='state',method='POST',body={'values':{}})):
            with self.assertRaises(w.ControlError): w.validate_job(job,BRIDGES)

    def test_rejects_arbitrary_command_or_body(self):
        for body in ({'cmd':'SetUser'},{'values':[]},{'values':{},'token':'fixture'}):
            with self.assertRaises(w.ControlError):w.validate_job(self.job(method='POST',resource='image',body=body),BRIDGES)

    def test_read_and_write_use_fixed_authenticated_bridge_contract(self):
        seen=[]
        class Opener:
            def open(self,request,timeout):
                seen.append(request)
                return Reply(json.dumps({'schemaVersion':1,'resources':[],'values':{}}).encode())
        w.dispatch(self.job(),BRIDGES,Opener())
        w.dispatch(self.job(method='POST',resource='image',body={'values':{'brightness':128}}),BRIDGES,Opener())
        self.assertEqual(seen[0].full_url,'http://192.168.30.210:8080/control/state')
        self.assertEqual(seen[1].get_header('X-reolink-control-intent'),'user')
        self.assertEqual(json.loads(seen[1].data),{'values':{'brightness':128}})

    def test_wrong_schema_does_not_escape_to_client(self):
        class Opener:
            def open(self,*args,**kwargs):return Reply(b'{"password":"fixture"}')
        with self.assertRaises(w.ControlError):w.dispatch(self.job(),BRIDGES,Opener())

    def test_config_socket_and_unix_identity_are_host_options_without_udm_group_lookup(self):
        env={'REOLINK_CONTROLS_CONFIG':'/etc/controls/config.json','REOLINK_CONTROLS_SOCKET':'/run/controls/worker.sock',
             'REOLINK_CONTROLS_SOCKET_UID':'1200','REOLINK_CONTROLS_SOCKET_GID':'992',
             'REOLINK_CONTROLS_SOCKET_DIR_MODE':'0750','REOLINK_CONTROLS_SOCKET_MODE':'0660'}
        args=w.arguments([],env)
        self.assertEqual(str(args.config).replace('\\','/'),'/etc/controls/config.json')
        self.assertEqual((args.socket_uid,args.socket_gid,args.socket_dir_mode,args.socket_mode),(1200,992,0o750,0o660))
        args=w.arguments(['--config','/custom/config.json','--socket-gid','123'],env)
        self.assertEqual(str(args.config).replace('\\','/'),'/custom/config.json')
        self.assertEqual(args.socket_gid,123)

    def test_invalid_identity_or_world_accessible_mode_is_rejected(self):
        for value in ('unifi-protect','-1','4294967295','1.5'):
            with self.subTest(value=value),self.assertRaises(Exception):w.numeric_identity(value)
        for value in ('0666','0777','888','1000'):
            with self.subTest(value=value),self.assertRaises(Exception):w.private_mode(value)

    def test_configurable_directory_and_socket_permissions_persist_for_host_tunnel(self):
        with tempfile.TemporaryDirectory()as directory:
            base=Path(directory).resolve();endpoint=base/'run'/'controls.sock'
            options=types.SimpleNamespace(config=base/'config.json',socket=endpoint,socket_uid=1200,socket_gid=992,
                socket_dir_mode=0o750,socket_mode=0o660)
            server=Mock();server.__enter__=Mock(return_value=server);server.__exit__=Mock(return_value=False)
            factory=Mock(return_value=server)
            with patch.object(w,'load_config',return_value=BRIDGES)as load, \
                 patch.object(w.os,'chown',create=True)as chown,patch.object(w.os,'chmod')as chmod, \
                 patch.object(w.os,'umask'):
                w.serve(options,factory)
            load.assert_called_once_with(options.config)
            factory.assert_called_once_with(str(endpoint),w.Handler)
            self.assertEqual(chown.call_args_list[0].args,(endpoint.parent,1200,992))
            self.assertEqual(chown.call_args_list[1].args,(endpoint,1200,992))
            self.assertEqual(chmod.call_args_list[0].args,(endpoint.parent,0o750))
            self.assertEqual(chmod.call_args_list[1].args,(endpoint,0o660))
            self.assertIs(server.bridges,BRIDGES);server.serve_forever.assert_called_once()

    def test_existing_non_socket_is_never_replaced(self):
        with tempfile.TemporaryDirectory()as directory:
            base=Path(directory).resolve();endpoint=base/'controls.sock';endpoint.write_bytes(b'keep')
            options=types.SimpleNamespace(config=base/'config.json',socket=endpoint,socket_uid=0,socket_gid=0,
                socket_dir_mode=0o750,socket_mode=0o660)
            with patch.object(w,'load_config',return_value=BRIDGES),patch.object(w.os,'chown',create=True), \
                 patch.object(w.os,'chmod'),patch.object(w.os,'umask'):
                with self.assertRaisesRegex(RuntimeError,'unexpected_socket_path'):w.serve(options,Mock())
            self.assertEqual(endpoint.read_bytes(),b'keep')

if __name__=='__main__':unittest.main()
