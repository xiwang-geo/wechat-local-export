import contextlib,hashlib,hmac,io,json,pathlib,sqlite3,struct,sys,tempfile,unittest
from Crypto.Cipher import AES
import zstandard
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import export_chat as e
from vendor.wal_snapshot import merge_committed_pages

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name)
        self.storage=self.base/'db_storage';(self.storage/'contact').mkdir(parents=True);(self.storage/'message').mkdir()
        c=sqlite3.connect(self.storage/'contact/contact.db')
        c.execute('create table contact(username,nick_name,remark,alias)')
        c.execute('insert into contact values(?,?,?,?)',('wxid_synthetic_peer','Demo','示例备注','demo_alias'));c.commit();c.close()
        self.table='Msg_'+hashlib.md5(b'wxid_synthetic_peer').hexdigest()
        for n,mapping in enumerate([[(1,'wxid_synthetic_self'),(2,'wxid_synthetic_peer')],[(1,'wxid_synthetic_peer'),(2,'wxid_synthetic_self')]]):
            c=sqlite3.connect(self.storage/f'message/message_{n}.db')
            c.execute('create table Name2Id(user_name text)')
            c.executemany('insert into Name2Id(rowid,user_name) values(?,?)',mapping)
            c.execute(f'create table {self.table}(local_id,server_id,local_type,sort_seq,real_sender_id,create_time,message_content)')
            content=zstandard.ZstdCompressor().compress('多行\n你好'.encode()) if n==0 else '回答'
            c.execute(f'insert into {self.table} values(1,?,1,?,1,?,?)',(n+1,n,1700000000+n,content));c.commit();c.close()
    def tearDown(self):self.tmp.cleanup()
    def contact(self):return e.select_contact(self.storage/'contact/contact.db','示例备注','demo_alias')
    def test_cross_shard_sender_mapping_and_compression(self):
        rows,counts,dup=e.read_rows(self.storage,self.contact(),'wxid_synthetic_self')
        self.assertEqual([r['sender'] for r in rows],['wxid_synthetic_self','wxid_synthetic_peer'])
        self.assertEqual(rows[0]['content'],'多行\n你好');self.assertEqual(sum(counts.values()),2);self.assertEqual(dup,0)
    def test_contact_ambiguity_and_expected_alias(self):
        c=sqlite3.connect(self.storage/'contact/contact.db');c.execute('insert into contact values(?,?,?,?)',('other','Other','示例备注','other_alias'));c.commit();c.close()
        with self.assertRaises(e.ExportError):e.select_contact(self.storage/'contact/contact.db','示例备注')
        self.assertEqual(self.contact()['alias'],'demo_alias')
        with self.assertRaises(e.ExportError):e.select_contact(self.storage/'contact/contact.db','示例备注','wrong_alias')
    def test_unknown_sender_fails(self):
        c=sqlite3.connect(self.storage/'message/message_1.db');c.execute('update Name2Id set user_name=? where rowid=1',('stranger',));c.commit();c.close()
        with self.assertRaises(e.ExportError):e.read_rows(self.storage,self.contact(),'wxid_synthetic_self')
    def test_malformed_text_fails(self):
        c=sqlite3.connect(self.storage/'message/message_1.db');c.execute(f'update {self.table} set message_content=?',(b'\xff\xff',));c.commit();c.close()
        with self.assertRaises(e.ExportError):e.read_rows(self.storage,self.contact(),'wxid_synthetic_self')
    def test_export_and_no_overwrite(self):
        output=self.base/'conversation.txt'
        args=['--snapshot-root',str(self.storage),'--self-id','wxid_synthetic_self','--contact','demo_alias','--output',str(output)]
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(e.main(args),0);original=output.read_bytes();self.assertEqual(e.main(args),1)
        self.assertEqual(output.read_bytes(),original)
        self.assertIn('多行\n你好',output.read_text(encoding='utf-8-sig'))
        receipt=json.loads(output.with_suffix('.receipt.json').read_text(encoding='utf-8'))
        self.assertEqual(receipt['messages'],2)
    def test_skill_output_rejected(self):
        with self.assertRaises(e.ExportError):e.validate_output(e.ROOT/'sensitive.txt')
    def test_quote_retains_both_speakers_and_multiline(self):
        from formatting import render
        xml='<msg><appmsg><type>57</type><title>回复\n下一行</title><refermsg><type>1</type><displayname>示例姓名</displayname><content>引用正文</content></refermsg></appmsg></msg>'
        body=render({'local_type':(57<<32)|49,'content':xml})
        self.assertIn('回复\n下一行',body);self.assertIn('示例姓名',body);self.assertIn('引用正文',body)
    def test_forwarded_history_is_separate_from_direct_messages(self):
        from formatting import render
        xml='<msg><appmsg><type>19</type><title>转发标题</title><recorditem>&lt;recordinfo&gt;&lt;datalist&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;虚构第三方&lt;/sourcename&gt;&lt;datadesc&gt;转发文字&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>'
        body=render({'local_type':(19<<32)|49,'content':xml})
        self.assertIn('转发的聊天记录',body);self.assertIn('虚构第三方',body);self.assertIn('转发文字',body)
    def test_snapshot_change_prevents_publication(self):
        output=self.base/'changed.txt'
        def fail():raise e.ExportError('source changed')
        with self.assertRaises(e.ExportError):e.export(self.storage,'demo_alias',None,'wxid_synthetic_self',output,output.with_suffix('.receipt.json'),'test',fail)
        self.assertFalse(output.exists())
    def test_duplicate_identity_includes_time(self):
        c=sqlite3.connect(self.storage/'message/message_1.db')
        c.execute(f'insert into {self.table} values(2,2,1,2,1,1700000001,?)',('回答',))
        c.execute(f'insert into {self.table} values(3,2,1,3,1,1700000002,?)',('回答',));c.commit();c.close()
        rows,_,dup=e.read_rows(self.storage,self.contact(),'wxid_synthetic_self')
        self.assertEqual(len(rows),3);self.assertEqual(dup,1)
    def test_authenticated_decryption_and_tamper(self):
        source=self.storage/'message/message_0.db';con=sqlite3.connect(source);con.execute('vacuum');con.close()
        plain=source.read_bytes();key=bytes(range(32));salt=bytes(range(16))
        mac=hashlib.pbkdf2_hmac('sha512',key,bytes(v^0x3a for v in salt),2,32)
        # Construct a synthetic encrypted page, independently of live user data.
        payload=bytearray(4096);payload[:16]=salt;iv=bytes(range(16,32));payload[4016:4032]=iv
        payload[16:4016]=AES.new(key,AES.MODE_CBC,iv).encrypt(plain[16:4016])
        payload[4032:]=hmac.new(mac,bytes(payload[16:4032])+struct.pack('<I',1),hashlib.sha512).digest()
        enc=self.base/'encrypted.db';enc.write_bytes(payload);out=self.base/'decrypted.db';e.decrypt(enc,out,key)
        self.assertEqual(out.read_bytes()[:4016],plain[:4016])
        payload[100]^=1;enc.write_bytes(payload)
        with self.assertRaises(e.ExportError):e.decrypt(enc,self.base/'tampered.db',key)
    def test_uncommitted_wal_is_not_published(self):
        from vendor.wal_snapshot import _checksum
        main=b'A'*4096;page=b'B'*4096
        header=struct.pack('>IIII',0x377f0682,3007000,4096,0)+b'12345678'
        state=_checksum(header,'<');wal=header+struct.pack('>II',*state)
        frame=struct.pack('>II',1,0)+b'12345678';state=_checksum(frame[:8]+page,'<',state)
        wal+=frame+struct.pack('>II',*state)+page
        self.assertEqual(merge_committed_pages(main,wal),main)
        frame=struct.pack('>II',1,1)+b'12345678';state=_checksum(frame[:8]+page,'<',_checksum(header,'<'))
        committed=wal[:32]+frame+struct.pack('>II',*state)+page
        self.assertEqual(merge_committed_pages(main,committed),page)
        bad=bytearray(committed);bad[-1]^=1
        with self.assertRaises(ValueError):merge_committed_pages(main,bytes(bad))

if __name__=='__main__':unittest.main()
