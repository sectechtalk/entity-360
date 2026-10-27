"""Wrap docs/entity-360_design.src.html into the single-file MHTML C:/src/mannequin/entity-360/entity-360_design.mhtml.
Run: python -I C:\\path\\to\\entity-360\\docs\\Build-DesignMhtml.py
The HTML is self-contained (inline CSS and SVG), so the archive holds one part."""
import base64, datetime, email, email.policy, hashlib, os, secrets

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'entity-360_design.src.html')
DST = os.path.join(os.path.dirname(HERE), 'entity-360_design.mhtml')

html = open(SRC, 'rb').read()
boundary = '----MultipartBoundary--' + secrets.token_urlsafe(36).replace('_', 'x').replace('-', 'y') + '----'
date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
b64 = base64.b64encode(html).decode('ascii')
lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]
head = ['From: <Saved by Claude Code>', 'Subject: Entity 360 design', 'Date: ' + date, 'MIME-Version: 1.0',
        'Content-Type: multipart/related;', '\ttype="text/html";', '\tboundary="' + boundary + '"', '', '',
        '--' + boundary, 'Content-Type: text/html; charset="utf-8"', 'Content-Transfer-Encoding: base64',
        'Content-Location: file:///entity-360_design.html', '']
body = '\r\n'.join(head + lines + ['--' + boundary + '--', ''])
open(DST, 'wb').write(body.encode('ascii'))

msg = email.message_from_bytes(open(DST, 'rb').read(), policy=email.policy.default)
parts = [p for p in msg.walk() if p.get_content_type() == 'text/html']
assert len(parts) == 1
back = parts[0].get_payload(decode=True)
print('written', DST, os.path.getsize(DST), 'bytes; round trip identical:', back == html, hashlib.sha256(back).hexdigest()[:16])
