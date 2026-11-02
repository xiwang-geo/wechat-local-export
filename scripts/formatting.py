"""Text formatting adapted from the local export workflow. No account constants."""
import datetime,xml.etree.ElementTree as ET,re,html
import zstandard
from vendor import appmsg
TZ=datetime.timezone(datetime.timedelta(hours=8))
def timefmt(t):return datetime.datetime.fromtimestamp(int(t),TZ).strftime('%Y-%m-%d %H:%M:%S')
def val(root,*tags):
 for tag in tags:
  el=root.find('.//'+tag)
  if el is not None and el.text:return html.unescape(el.text)
 return ''
def plainxml(text):
 try:
  root=ET.fromstring(text)
  return '\n'.join(dict.fromkeys(v.strip() for v in root.itertext() if v.strip()))
 except ET.ParseError:return text
def history(text,depth=0):
 if depth>8:return '[嵌套过深，以下保留原始内容] '+text
 try:
  root=ET.fromstring(text)
 except ET.ParseError:
  return plainxml(text)
 record=root.find('.//recorditem')
 if record is not None and record.text:
  try:root=ET.fromstring(record.text)
  except ET.ParseError:pass
 lines=[]
 for item in root.findall('.//dataitem'):
  who=val(item,'sourcename','realchatname') or '未知发送者'
  ts=val(item,'sourcetime')
  if ts.isdigit():ts=timefmt(ts)
  dtype=int(item.attrib.get('datatype','0') or 0)
  desc=val(item,'datadesc'); title=val(item,'datatitle'); nested=val(item,'recordxml','recorditem')
  if nested:body=history(nested,depth+1)
  elif dtype==1:body=desc or title
  else:
   label={2:'图片',3:'语音',4:'视频',5:'链接',6:'位置',7:'音乐',8:'文件',14:'聊天记录',19:'引用消息',22:'小程序'}.get(dtype,f'转发内容类型 {dtype}')
   body=f'[{label}] '+ '\n'.join(dict.fromkeys(v for v in [title,desc] if v))
  lines.append(f'  {ts} {who}\n'+ '\n'.join('    '+s for s in body.splitlines()))
 return '\n'.join(lines) if lines else plainxml(text)
def render(r):
 text=r['content']; typ=r['local_type']&0xffffffff
 if typ==1:return text
 if typ in (3,43,47):return {3:'[图片]',43:'[视频]',47:'[表情]'}[typ]
 if typ==34:
  m=re.search(r'(?:voicelength|length)=["\'](\d+)',text)
  return '[语音'+(f' {int(m.group(1))/1000:g}秒' if m else '')+'，未转写]'
 if typ==49:
  p=appmsg.parse_app_message(text,r['local_type'])
  if p['kind']=='chat_history':return '[转发的聊天记录] '+p.get('title','')+'\n'+history(text)
  if p['kind']=='quote':
   quoted=p.get('quoted_content','')
   if quoted.lstrip().startswith('<'):
    qt=int(p.get('quoted_type',0))
    quoted=render({'content':quoted,'local_type':qt}) if qt else plainxml(quoted)
   return p.get('title','')+'\n[引用 '+p.get('quoted_sender','')+'：'+quoted+']'
  return '['+p['label']+'] '+p['summary']
 if typ in (10000,10002):
  if text.lstrip().startswith('<'):
   try:
    root=ET.fromstring(text); content=val(root,'replacemsg','template','content','title')
    if content:
     fields={e.tag:e.text for e in root.iter() if e.text}
     return re.sub(r'\$\{([^}]+)\}',lambda m:fields.get(m.group(1),m.group(0)),content)
   except ET.ParseError:pass
   return plainxml(text)
  return text
 if typ==48:
  try:
   root=ET.fromstring(text); loc=root.find('.//location')
   if loc is not None:return '[位置] '+'；'.join(f'{k}={v}' for k,v in loc.attrib.items() if k in ('label','poiname','x','y'))
  except ET.ParseError:pass
  return '[位置] '+plainxml(text)
 if typ==42:
  try:
   root=ET.fromstring(text);return '[名片] '+'；'.join(f'{k}={v}' for k,v in root.attrib.items() if k in ('nickname','username','alias','province','city'))
  except ET.ParseError:pass
  return '[名片] '+plainxml(text)
 if typ==50:return '[通话] '+plainxml(text)
 return f'[消息类型 {r["local_type"]}] '+plainxml(text)
