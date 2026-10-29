#!/usr/bin/env python3
#
# Regenerates the libFuzzer dictionaries fuzz/fuzz-<name>/<name>.dict
#
# Written in 2010 - 2026 Andy Green <andy@warmcat.com>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# Some of the tokens come from lws' own tables (the h1 lexer's header names,
# the names lhp, svg and the hl drivers know), so run it again when those
# change:  python3 fuzz/gen-dicts.py
#

import re, sys, os

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def lits(path, pat=r'"([a-z][a-z0-9-]{1,30})"'):
    return sorted(set(re.findall(pat, open(os.path.join(R,path)).read())))
def esc(b):
    out=''
    for c in b.encode() if isinstance(b,str) else b:
        if c in (0x22,0x5c) or c<0x20 or c>0x7e: out+='\\x%02x'%c
        else: out+=chr(c)
    return '"'+out+'"'
def write(name, header, toks):
    seen=[]; 
    for t in toks:
        if t not in seen: seen.append(t)
    with open(os.path.join(R,'fuzz','fuzz-'+name,name+'.dict'),'w') as f:
        f.write('#\n# libFuzzer dictionary for fuzz-%s, made by fuzz/gen-dicts.py\n#\n'%name)
        for l in header: f.write('# '+l+'\n')
        f.write('#\n\n')
        for t in seen: f.write(esc(t)+'\n')

# h1: the lws header lexer's own table, both cases, and the values that
# switch parser states
lex=re.findall(r'^\s*"([^"]*)",', open(R+'/lib/sansio/http/lextable-strings.h').read(), re.M)
lex=[bytes(x,'ascii').decode('unicode_escape') for x in lex]
h1=[]
for x in lex:
    if x in ('\r\n',''): continue
    h1.append(x)
    if x.endswith(':'): h1.append('-'.join(p.capitalize() for p in x.split('-')))
    if x.endswith(' ') and x[0].isalpha(): h1.append(x.upper())
h1+=['\r\n','\r\n\r\n',' HTTP/1.1\r\n',' HTTP/1.0\r\n','HTTP/1.1 ','HTTP/2.0','chunked','keep-alive','close',
 'Upgrade','websocket','h2c','100-continue','gzip','deflate','br','identity','bytes=','bytes=0-','-',',',';','=',
 '0\r\n\r\n','permessage-deflate','client_max_window_bits','server_max_window_bits','client_no_context_takeover',
 'server_no_context_takeover','13','dGhlIHNhbXBsZSBub25jZQ==','multipart/form-data; boundary=',
 'application/x-www-form-urlencoded','text/plain','Basic ','Digest ','realm=','nonce=','/','/..','/./','%2e%2e','%00',
 '?','&','#','*','http://','https://','Host: fuzz\r\n','Content-Length: ','Transfer-Encoding: chunked\r\n']
write('h1',['Header names are the h1 lexer table (lib/sansio/http/lextable-strings.h)',
            'in its lower case and in the usual capitalisation, then values that',
            'steer the parser and the upgrades it can make.'],h1)

# h2: frame headers of each type, the client preface pieces, hpack static
# table names and the pseudo-headers
h2=[]
for t in range(0,10):
    for fl in (0,1,4,5,8,0x20,0x24,0x25):
        h2.append(bytes([0,0,0,t,fl,0,0,0,1]))
h2+=[bytes([0,0,0,4,0,0,0,0,0]), bytes([0,0,0,4,1,0,0,0,0]), bytes([0,0,4,8,0,0,0,0,0])]
for i in range(1,7): h2.append(bytes([0,i]))      # settings ids
h2+=[b'\x7f\xff\xff\xff', b'\x00\x00\x40\x00', b'\xff\xff\xff\xff', b'\x80\x00\x00\x00']
hp=[':authority',':method',':path',':scheme',':status',':protocol','GET','POST','CONNECT','websocket','http','https',
 'content-length','content-type','cookie','te','trailers','connection','host','accept-encoding','user-agent',
 'transfer-encoding','upgrade','keep-alive','proxy-connection']
for x in hp:
    h2.append(x); h2.append(bytes([len(x)])+x.encode()); h2.append(b'\x00'+bytes([len(x)])+x.encode())
for i in (0x82,0x83,0x84,0x85,0x86,0x87,0x3f,0x20,0x3fe11f,0x40,0x10,0x00,0xff):
    if i<256: h2.append(bytes([i]))
write('h2',['Input is h2 frames: whole frame headers of each type with the flags',
            'that matter, SETTINGS ids, window extremes, and hpack: indexed static',
            'entries, table size updates and the header names as literals.'],h2)

# lejp / jose: json syntax, and the jose member names and algorithms
js=['{','}','[',']',':',',','"','""','{}','[]','true','false','null','-0','0.0','1e308','-1e-308',
 '9223372036854775807','18446744073709551616','"\\u0000"','"\\ud800"','"\\udc00"','"\\\\"','"\\/"','\\u']
write('lejp',['json syntax, escapes and number edge cases.'],js)
jose=js+['"alg"','"enc"','"kty"','"crv"','"kid"','"use"','"key_ops"','"x"','"y"','"d"','"n"','"e"','"p"','"q"',
 '"dp"','"dq"','"qi"','"k"','"zip"','"typ"','"cty"','"crit"','"jku"','"jwk"','"x5c"','"x5u"','"epk"','"apu"','"apv"',
 '"iv"','"tag"','"p2s"','"p2c"','"protected"','"header"','"payload"','"signature"','"signatures"','"recipients"',
 '"encrypted_key"','"ciphertext"','"aad"','"keys"','"RSA"','"EC"','"oct"','"OKP"','"P-256"','"P-384"','"P-521"',
 '"Ed25519"','"none"','"HS256"','"HS384"','"HS512"','"RS256"','"RS384"','"RS512"','"ES256"','"ES384"','"ES512"',
 '"PS256"','"RSA1_5"','"RSA-OAEP"','"RSA-OAEP-256"','"A128KW"','"A256KW"','"dir"','"ECDH-ES"','"ECDH-ES+A128KW"',
 '"A128GCM"','"A256GCM"','"A128CBC-HS256"','"A256CBC-HS512"','"DEF"','.','..','eyJ','AAAA']
write('jose',['json syntax, and the JOSE / JWK member names and algorithm names.'],jose)

# lhp and lhp-layout: tag and property names lhp knows, and html / css
# syntax
lhp=lits('lib/misc/lhp.c')+lits('lib/misc/lhp-ss.c') if os.path.exists(R+'/lib/misc/lhp-ss.c') else lits('lib/misc/lhp.c')
lhp=[x for x in lhp]
syn=['<!DOCTYPE html>','<!--','-->','<','</','>','/>','="','"',"'",'=','&amp;','&lt;','&#x','&#','&nbsp;',
 '<style>','</style>','<html>','<head>','<body>','<div','<span','<img src="','<a href="','<table>','<tr>','<td>',
 '<br>','<p>','style="','class="','id="','{','}',':',';',',','.','#','*','>','+','~','[',']','(',')','!important',
 '@media','@font-face','@import','px','em','rem','%','vh','vw','pt','#fff','#000000','rgb(','rgba(','url(','calc(',
 'inherit','initial','auto','none','0','-1','99999999','1.5']
write('lhp',['Tag, attribute, property and value names lhp knows (string literals',
             'of lib/misc/lhp.c), then html and css syntax.'],syn+lhp)
write('lhp-layout',['As lhp.dict: tag, attribute, property and value names lhp knows',
             '(string literals of lib/misc/lhp.c), then html and css syntax.'],syn+lhp)

# svg
svg=['<svg','</svg>','<?xml version="1.0"?>','<!--','-->','<','</','/>','>','="','"',"'",'xmlns="http://www.w3.org/2000/svg"',
 'viewBox="','width="','height="','d="','M','m','L','l','H','h','V','v','C','c','S','s','Q','q','T','t','A','a','Z','z',
 'transform="','matrix(','translate(','rotate(','scale(','skewX(','skewY(','#','#fff','rgb(','url(#','none',
 'e-5','1e9','-',',','.',' ','%','px']+lits('lib/misc/svg.c')
write('svg',['svg and xml syntax, path commands, transforms, then the element,',
             'attribute and value names lib/misc/svg.c knows.'],svg)

# hl: the language drivers' keywords and the markup of each
hl=lits('lib/misc/hl-c.c')+['#include','#define','#if','/*','*/','//','"','\\"',"'",'\\','0x','1e','0b','u8"','L"',
 'R"(',')"','@@ -1,2 +1,2 @@','--- a/','+++ b/','diff --git a/','\n+','\n-','\n ','<','</','>','<!--','-->','&amp;',
 '```','```c\n','```diff\n','```html\n','\n```\n']
write('hl',['C keywords from lib/misc/hl-c.c, then the syntax the c, diff and html',
            'drivers classify, and markdown fences.'],hl)

md=['# ','## ','###### ','\n','\n\n','    ','\t','> ','- ','* ','+ ','1. ','1) ','---','***','___','```','~~~','`',
 '**','__','*','_','~~','[','](',')','![','<','>','<http://','\\','&amp;','&#','|','| --- |','|:---:|',':','---:',
 '- [ ] ','- [x] ','[^1]','[^1]: ','<div>','</div>','<!--','-->','http://','https://','www.']
write('md',['markdown block and inline syntax, gfm tables, task lists, footnotes',
            'and autolinks.'],md)
