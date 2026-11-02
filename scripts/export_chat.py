"""Export one authorized Windows WeChat 4.x conversation without modifying WeChat."""
import argparse,collections,datetime,hashlib,hmac,json,os,pathlib,re,sqlite3,struct,sys,tempfile
from Crypto.Cipher import AES
import zstandard
from vendor.wal_snapshot import read_snapshot
from formatting import render,timefmt

ROOT=pathlib.Path(__file__).resolve().parents[1]
class ExportError(Exception): pass

def decode(value):
    if value is None:return ''
    if isinstance(value,str):return value
    value=bytes(value)
    if value.startswith(b'\x28\xb5\x2f\xfd'):
        value=zstandard.ZstdDecompressor().decompress(value,max_output_size=64*1024*1024)
    return value.decode('utf-8',errors='strict')

def account_root(root,account=None):
    candidates=sorted(p for p in root.iterdir() if p.is_dir() and (p/'db_storage/contact/contact.db').is_file())
    if account:
        candidates=[p for p in candidates if p.name==account]
    if len(candidates)!=1:
        raise ExportError('Specify --account; matching account directories: '+', '.join(p.name for p in candidates))
    return candidates[0]

def db_files(storage):
    shards=sorted((storage/'message').glob('message_*.db'))
    shards=[p for p in shards if re.fullmatch(r'message_\d+\.db',p.name)]
    if not shards:raise ExportError('No ordinary message shards found')
    return [storage/'contact/contact.db',*shards]

def stamp(files):
    result={}
    for p in files:
        for path in (p,pathlib.Path(str(p)+'-wal')):
            try:s=path.stat();result[str(path)]=(s.st_size,s.st_mtime_ns)
            except FileNotFoundError:result[str(path)]=None
    return result

def decrypt(src,dst,key):
    data=read_snapshot(str(src),attempts=5)
    if len(data)<4096 or len(data)%4096:raise ExportError('Invalid encrypted database size')
    enc=key[:32];salt=key[32:] or data[:16]
    if len(enc)!=32 or len(salt)!=16:raise ExportError('Invalid verified key shape')
    mac=hashlib.pbkdf2_hmac('sha512',enc,bytes(v^0x3a for v in salt),2,32)
    dst.parent.mkdir(parents=True,exist_ok=True)
    with dst.open('xb') as output:
        for i in range(len(data)//4096):
            page=data[i*4096:(i+1)*4096];offset=16 if i==0 else 0
            sig=hmac.new(mac,page[offset:4032]+struct.pack('<I',i+1),hashlib.sha512).digest()
            if not hmac.compare_digest(sig,page[4032:]):raise ExportError(f'Encrypted page authentication failed (page {i+1})')
            plain=AES.new(enc,AES.MODE_CBC,page[4016:4032]).decrypt(page[offset:4016])
            output.write((b'SQLite format 3\x00' if i==0 else b'')+plain+bytes(80))

def connect(path):
    conn=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA query_only=ON')
    try:
        if conn.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ExportError('SQLite integrity check failed')
    except BaseException:conn.close();raise
    return conn

def select_contact(path,query,expected=None):
    con=connect(path)
    try:
        found=con.execute('SELECT username,nick_name,remark,alias FROM contact WHERE username=? OR alias=? OR remark=? OR nick_name=?',(query,)*4).fetchall()
    finally:con.close()
    if expected is not None:found=[r for r in found if r['alias']==expected]
    if len(found)!=1:raise ExportError(f'Contact matched {len(found)} records; use an exact alias/wxid and optional --expect-alias')
    return dict(found[0])

def read_rows(storage,contact,self_id):
    table='Msg_'+hashlib.md5(contact['username'].encode('utf-8')).hexdigest()
    rows=[];counts={}
    for path in db_files(storage)[1:]:
        con=connect(path)
        try:
            if not con.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?',('table',table)).fetchone():counts[path.name]=0;continue
            batch=con.execute(f'SELECT m.*, n.user_name AS sender FROM {table} m LEFT JOIN Name2Id n ON n.rowid=m.real_sender_id').fetchall()
            counts[path.name]=len(batch)
            for rr in batch:
                r={k:rr[k] for k in ('local_id','server_id','local_type','sort_seq','create_time','sender')}
                r['database']=path.name
                base=r['local_type']&0xffffffff
                if base not in (10000,10002) and r['sender'] not in (self_id,contact['username']):
                    raise ExportError(f'Unknown sender in {path.name}, local message {r["local_id"]}')
                # Opaque media bodies may contain non-text bytes. They are placeholders,
                # not text decoding failures. Voice length metadata is parsed if textual.
                try:r['content']=decode(rr['message_content'])
                except (UnicodeError,zstandard.ZstdError):
                    if base not in (3,34,43,47):raise ExportError(f'Cannot decode body in {path.name}, local message {r["local_id"]}')
                    r['content']=''
                rows.append(r)
        finally:con.close()
    rows.sort(key=lambda r:(r['create_time'],r['sort_seq'] or 0,r['database'],r['local_id']))
    unique=[];seen=set()
    for r in rows:
        identity=(r['server_id'],r['create_time'],r['local_type'],r['content'],r['sender']) if r['server_id'] else (r['database'],r['local_id'])
        if identity not in seen:seen.add(identity);unique.append(r)
    return unique,counts,len(rows)-len(unique)

def validate_output(output):
    output=output.resolve()
    if output==ROOT or ROOT in output.parents:raise ExportError('Choose an output outside the skill repository')
    if output.suffix.lower()!='.txt':raise ExportError('Output must use .txt extension')
    receipt=output.with_suffix('.receipt.json')
    if output.exists() or receipt.exists():raise ExportError('Output or receipt already exists; choose a new filename')
    output.parent.mkdir(parents=True,exist_ok=True)
    return output,receipt

def publish(path,text,encoding):
    # Same-directory hardlink publishes a complete file without overwriting a race winner.
    fd,tmp=tempfile.mkstemp(prefix='.wechat-export-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding=encoding,newline='\r\n') as f:f.write(text)
        os.link(tmp,path)
    finally:os.unlink(tmp)

def export(storage,query,expected,self_id,output,receipt,verification,check_source=None):
    contact=select_contact(storage/'contact/contact.db',query,expected)
    rows,counts,duplicates=read_rows(storage,contact,self_id)
    if not rows:raise ExportError('No messages found for the selected contact')
    name=contact['remark'] or contact['nick_name'] or '对方'
    body=[f'我与{name}的微信本地聊天记录',f'昵称：{contact["nick_name"]}',f'微信号：{contact["alias"]}',f'消息数量：{len(rows)}',f'范围：{timefmt(rows[0]["create_time"])} 至 {timefmt(rows[-1]["create_time"])}（北京时间）','范围仅限本机现存记录；图片、视频、表情以标记保留；语音未转写。','']
    for i,r in enumerate(rows,1):
        who='系统' if (r['local_type']&0xffffffff) in (10000,10002) else ('我' if r['sender']==self_id else name)
        body.append(f'[{timefmt(r["create_time"])}] {who}  #{i}\n{render(r) or "[空白消息]"}\n')
    result={'messages':len(rows),'raw_messages':sum(counts.values()),'duplicates_removed':duplicates,'shards':counts,'first':timefmt(rows[0]['create_time']),'last':timefmt(rows[-1]['create_time']),'timezone':'Asia/Shanghai','verification':verification,'decode_errors':0,'unknown_senders':0,'media':'placeholders; voice not transcribed','contact_verified':True}
    if check_source is not None:check_source()
    publish(output,'\n'.join(body),'utf-8-sig')
    publish(receipt,json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    return result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--data-root',type=pathlib.Path,help='xwechat_files directory (Windows live mode)')
    mode.add_argument('--snapshot-root',type=pathlib.Path,help='Existing authorized plaintext db_storage (no memory access)')
    parser.add_argument('--account',help='Exact account directory basename')
    parser.add_argument('--self-id',help='Required with --snapshot-root; own internal wxid')
    parser.add_argument('--contact',required=True)
    parser.add_argument('--expect-alias')
    parser.add_argument('--output',required=True,type=pathlib.Path)
    args=parser.parse_args(argv)
    try:
        output,receipt=validate_output(args.output)
        if args.snapshot_root:
            if not args.self_id:raise ExportError('--self-id is required with --snapshot-root')
            storage=args.snapshot_root.resolve();files=db_files(storage);before=stamp(files)
            def stable():
                if stamp(files)!=before or db_files(storage)!=files:raise ExportError('Snapshot changed during export')
            result=export(storage,args.contact,args.expect_alias,args.self_id,output,receipt,'existing plaintext; SQLite quick_check; source completeness not proven',stable)
        else:
            if os.name!='nt':raise ExportError('Live key extraction supports Windows only')
            account=account_root(args.data_root.resolve(),args.account)
            storage=account/'db_storage';files=db_files(storage);before=stamp(files)
            from vendor.keyscan import KeyScanner
            pairs=[(p.relative_to(storage).as_posix(),str(p),p.stat().st_size) for p in files]
            keys=KeyScanner(pairs).extract_keys()
            if len(keys)!=len(pairs):raise ExportError('Not all required keys verified; incompatible client layout or insufficient process read access')
            with tempfile.TemporaryDirectory(prefix='.wechat-private-',dir=output.parent) as temp:
                plain=pathlib.Path(temp)
                for rel,path,_ in pairs:decrypt(pathlib.Path(path),plain/rel,keys[rel])
                keys.clear()
                if stamp(files)!=before or db_files(storage)!=files:raise ExportError('WeChat databases changed; retry when idle')
                own=re.sub(r'_[A-Za-z0-9]{4}$','',account.name)
                result=export(plain,args.contact,args.expect_alias,own,output,receipt,'all encrypted pages HMAC; committed WAL; SQLite quick_check')
        print(json.dumps(result,ensure_ascii=False,indent=2))
        print('TXT:',output);print('Receipt:',receipt)
        return 0
    except (ExportError,OSError,sqlite3.Error,ValueError,RuntimeError) as exc:
        print('Export stopped:',str(exc),file=sys.stderr);return 1

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    raise SystemExit(main())
