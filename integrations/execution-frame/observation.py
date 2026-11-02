"""Executor-owned observation adapter. No ambient reads, command execution or grants."""
import copy
import re
import secrets

MAX_BYTES = 65536
FLAGS = ("noglob", "nullglob", "failglob", "dotglob", "nocaseglob",
         "globstar", "extglob", "globskipdots")
SHELL_VALUES = ("globignore", "lc_all", "lc_collate", "lc_ctype", "lang")


class ObservationUnavailable(ValueError):
    """The caller must omit the observation and preserve the guard's Ask."""


class _LiteralDeclaration:
    """Parse the literal subset emitted by declare -p, never Shell source/eval."""
    def __init__(self, text):
        self.text, self.pos = text, 0

    def word(self, stops=""):
        out = bytearray()
        text = self.text
        while self.pos < len(text) and text[self.pos] not in stops:
            c = text[self.pos]
            self.pos += 1
            if c == '"':
                while self.pos < len(text) and text[self.pos] != '"':
                    ch = text[self.pos]; self.pos += 1
                    if ch == '\\':
                        if self.pos == len(text): raise ValueError('truncated quote')
                        nxt=text[self.pos]; self.pos += 1
                        if nxt not in '\\"$`': out.extend(b'\\')
                        ch=nxt
                    elif ch in '$`': raise ValueError('expansion is not a literal')
                    out.extend(ch.encode('utf-8'))
                if self.pos == len(text): raise ValueError('unclosed quote')
                self.pos += 1
            elif c == "'":
                end=text.find("'", self.pos)
                if end < 0: raise ValueError('unclosed quote')
                out.extend(text[self.pos:end].encode('utf-8')); self.pos=end+1
            elif c == '$' and text[self.pos:self.pos+1] == "'":
                self.pos += 1
                escapes={'a':7,'b':8,'e':27,'E':27,'f':12,'n':10,'r':13,'t':9,'v':11,
                         '\\':92,"'":39,'"':34,'?':63}
                while self.pos<len(text) and text[self.pos]!="'":
                    ch=text[self.pos];self.pos+=1
                    if ch!='\\':out.extend(ch.encode('utf-8'));continue
                    if self.pos==len(text):raise ValueError('truncated ANSI quote')
                    ch=text[self.pos];self.pos+=1
                    if ch in escapes:out.append(escapes[ch])
                    elif ch in '01234567':
                        digits=ch
                        while len(digits)<3 and self.pos<len(text) and text[self.pos] in '01234567':
                            digits+=text[self.pos];self.pos+=1
                        number=int(digits,8)
                        if number>255:raise ValueError('oversized escape')
                        out.append(number)
                    elif ch=='x':
                        match=re.match(r'[0-9a-fA-F]{1,2}',text[self.pos:])
                        if not match:raise ValueError('invalid hex escape')
                        self.pos+=len(match[0]);out.append(int(match[0],16))
                    else:raise ValueError('unsupported ANSI escape')
                if self.pos==len(text):raise ValueError('unclosed ANSI quote')
                self.pos+=1
            elif c=='\\':
                if self.pos==len(text):raise ValueError('truncated escape')
                out.extend(text[self.pos].encode('utf-8'));self.pos+=1
            elif c in '$`();\n\r':raise ValueError('nonliteral declaration')
            else:out.extend(c.encode('utf-8'))
            if len(out)>8192:raise ValueError('literal exceeds budget')
        value=out.decode('utf-8',errors='strict')
        if '\0' in value:raise ValueError('NUL declaration')
        return value


def _declaration(name, status, text):
    if status in ('absent','unknown'):
        if text:raise ObservationUnavailable('presence tag carries declaration bytes')
        return dict(kind=status)
    if status!='declaration':raise ObservationUnavailable('invalid declaration tag')
    match=re.fullmatch(r'declare -([A-Za-z]*|-) ([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?',text,re.S)
    if not match or match[2]!=name:return dict(kind='unknown')
    flags=set(match[1]) - {'-'};body=match[3]
    if body is None:return dict(kind='unknown')
    try:
        parser=_LiteralDeclaration(body)
        if 'n' in flags:
            if flags-set('nx'):return dict(kind='unsupported')
            target=parser.word()
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}',target):return dict(kind='unsupported')
            return dict(kind='name_reference',target=target)
        if flags & set('aA'):
            if flags-set('aAx') or ('a' in flags and 'A' in flags):return dict(kind='unsupported')
            # Older Bash emits the entire literal array body in one quote.
            if body.startswith("'"):
                body=parser.word()
                if parser.pos!=len(parser.text):raise ValueError('quoted array tail')
                parser=_LiteralDeclaration(body)
            if not body.startswith('('):return dict(kind='unknown')
            parser.pos=1;elements=[];keys=set()
            while parser.pos<len(body):
                while parser.pos<len(body) and body[parser.pos] in ' \t':parser.pos+=1
                if parser.pos<len(body) and body[parser.pos]==')':parser.pos+=1;break
                if parser.pos==len(body) or body[parser.pos]!='[':raise ValueError('missing index')
                parser.pos+=1;key=parser.word(']')
                if body[parser.pos:parser.pos+2]!=']=':raise ValueError('invalid index')
                parser.pos+=2;value=parser.word(' \t)')
                if 'a' in flags:
                    if not re.fullmatch(r'0|[1-9][0-9]*',key):raise ValueError('nonliteral array index')
                    key=int(key)
                    if key>2**63-1:raise ValueError('array index exceeds budget')
                elif not key:raise ValueError('empty associative key')
                if key in keys or len(elements)>=256:raise ValueError('duplicate or oversized array')
                keys.add(key);elements.append([key,value])
            if parser.pos!=len(body) or not body.endswith(')'):raise ValueError('array tail')
            if 'a' in flags:return dict(kind='indexed_array',elements=elements,complete=True)
            return dict(kind='associative_array',elements=elements)
        if flags-set('ix'):return dict(kind='unsupported')
        value=parser.word()
        if 'i' in flags and not re.fullmatch(r'[+-]?[0-9]+',value):return dict(kind='unknown')
        return dict(kind='scalar',value=value,integer='i' in flags)
    except (ValueError,UnicodeError,IndexError):
        return dict(kind='unknown')


def _declarations(variables, fields):
    if not fields or fields[0]!='caushell-shell-declarations-v1' or fields[-1]!='END' or (len(fields)-2)%3:
        raise ObservationUnavailable('incomplete declaration channel')
    if (len(fields)-2)//3>2048:raise ObservationUnavailable('declaration count exceeds budget')
    raw={};values={}
    for index in range(1,len(fields)-1,3):
        name,status,text=fields[index:index+3]
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}',name):raise ObservationUnavailable('invalid declaration name')
        if name in raw and raw[name]!=(status,text):raise ObservationUnavailable('conflicting declaration observations')
        raw[name]=(status,text);values[name]=_declaration(name,status,text)
    if len(values)>128 or any(name not in values for name in variables):
        raise ObservationUnavailable('missing or oversized variable declarations')
    reachable=set(variables)
    for _ in range(128):
        before=len(reachable)
        for name in tuple(reachable):
            value=values[name]
            if value['kind']=='name_reference':
                target=value['target']
                if target not in values:raise ObservationUnavailable('nameref target is missing')
                reachable.add(target)
        if len(reachable)==before:break
    if set(values)!=reachable:raise ObservationUnavailable('unplanned declaration observation')
    for root in variables:
        current=root;seen=set()
        for _ in range(16):
            if current in seen:
                values[root]=dict(kind='unknown');break
            seen.add(current);value=values[current]
            if value['kind']!='name_reference':break
            current=value['target']
        else:values[root]=dict(kind='unknown')
    # Drop facts whose root became Unknown; they cannot authorize another name.
    reachable=set(variables)
    for _ in range(16):
        before=len(reachable)
        for name in tuple(reachable):
            if values[name]['kind']=='name_reference':reachable.add(values[name]['target'])
        if len(reachable)==before:break
    return [dict(name=name,value=value) for name,value in values.items() if name in reachable]


def planned_names(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get("binding"), dict):
        raise ObservationUnavailable("invalid observation binding")
    req = plan.get("requirements")
    if not isinstance(req, dict):
        raise ObservationUnavailable("invalid observation requirements")
    names = req.get("environment_names")
    if (not isinstance(names, list) or len(names) > 128
            or any(not isinstance(n, str) or len(n) > 256
                   or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", n) for n in names)
            or len(set(names)) != len(names)
            or not isinstance(req.get("pathname"), bool)):
        raise ObservationUnavailable("invalid or unbounded observation plan")
    return tuple(names)


def planned_variables(plan):
    names = plan.get("requirements", {}).get("variable_names", [])
    if (not isinstance(names, list) or len(names) > 128
            or len(set(n for n in names if isinstance(n, str))) != len(names)
            or any(not isinstance(n, str) or len(n) > 256
                   or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", n) for n in names)):
        raise ObservationUnavailable("invalid shell scalar plan")
    return tuple(names)


def planned_natives(plan):
    names=plan.get('requirements',{}).get('native_command_names',[])
    if (not isinstance(names,list) or len(names)>16 or len(set(n for n in names if isinstance(n,str)))!=len(names)
            or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}',n) for n in names)):
        raise ObservationUnavailable('invalid native command plan')
    return tuple(names)


def decode(plan, nonce, raw):
    """Decode bytes from the trusted owning-frame channel, never tool_input."""
    names = planned_names(plan)
    variables = planned_variables(plan)
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES or not raw.endswith(b"\0"):
        raise ObservationUnavailable("capture is missing, truncated, or oversized")
    try:
        fields = raw[:-1].decode("utf-8", errors="strict").split("\0")
    except UnicodeError as e:
        raise ObservationUnavailable("capture is not representable as UTF-8") from e
    natives=planned_natives(plan)
    native_executables={}
    if natives:
        tail=2+3*len(natives)
        if len(fields)<tail or fields[-tail]!='caushell-native-executables-v1' or fields[-1]!='END':
            raise ObservationUnavailable('missing native executable channel')
        rows=fields[-tail+1:-1]
        for i,name in enumerate(natives):
            got,kind,path=rows[3*i:3*i+3]
            if got!=name or kind not in ('file','unavailable') or (kind=='unavailable' and path) or (kind=='file' and (not path.startswith('/') or len(path)>4096)):
                raise ObservationUnavailable('invalid owning executable lookup')
            native_executables[name]=dict(kind=kind,path=path)
        fields=fields[:-tail]
    width = 3
    marker = 21 + 3 * len(names)
    if variables and len(fields) > marker and fields[marker] == "caushell-shell-scalars-v2":
        width = 4
    variable_values = []
    legacy_end = 21 + 3 * len(names) + (2 + width * len(variables) if variables else 0)
    if variables and len(fields)>legacy_end:
        variable_values=_declarations(variables,fields[legacy_end:])
        fields=fields[:legacy_end]
    if len(fields) != 21 + 3 * len(names) + (2 + width * len(variables) if variables else 0):
        raise ObservationUnavailable("capture field count differs from the plan")
    if fields[:2] != ["caushell-bash-frame-v1", nonce] or fields[-1] != "END":
        raise ObservationUnavailable("capture protocol or executor nonce mismatch")
    position = 2
    pathname = {}
    for flag in FLAGS:
        word = fields[position]
        position += 1
        if word not in ("0", "1"):
            raise ObservationUnavailable("invalid pathname flag")
        pathname[flag] = word == "1"

    def value():
        nonlocal position
        status, text = fields[position:position + 2]
        position += 2
        if status not in ("present", "absent", "unknown"):
            raise ObservationUnavailable("invalid presence tag")
        if status != "present" and text:
            raise ObservationUnavailable("absence or unknown carries an invented value")
        return dict(status=status, **({"value": text} if status == "present" else {}))

    for name in SHELL_VALUES:
        pathname[name] = value()
    environment = []
    for expected in names:
        if fields[position] != expected:
            raise ObservationUnavailable("unexpected, reordered, or duplicate name")
        position += 1
        environment.append(dict(name=expected, value=value()))
    if fields[position] != "END":
        raise ObservationUnavailable("unexpected capture tail")
    scalars = []
    integers = []
    if variables:
        position += 1
        if fields[position] not in ("caushell-shell-scalars-v1", "caushell-shell-scalars-v2"):
            raise ObservationUnavailable("missing shell scalar channel")
        position += 1
        for expected in variables:
            if fields[position] != expected:
                raise ObservationUnavailable("unexpected shell scalar name")
            position += 1
            if width == 4:
                integer = fields[position]
                position += 1
                if integer not in ("0", "1"):
                    raise ObservationUnavailable("invalid integer scalar tag")
                if integer == "1":
                    integers.append(expected)
            scalars.append(dict(name=expected, value=value()))
    if position != len(fields) - 1:
        raise ObservationUnavailable("unexpected capture tail")
    result = dict(binding=copy.deepcopy(plan["binding"]), environment=environment,
                  pathname=pathname if plan["requirements"]["pathname"] else None)
    if variables:
        result["variables"] = scalars
        if variable_values:result['variable_values']=variable_values
        if integers:
            result["integer_variables"] = integers
    if natives:result["_native_executables"]=native_executables
    return result


def collect(plan, owning_executor_capture):
    """Pause/collect through the owning executor; never start a probe Shell."""
    names = planned_names(plan)
    variables = planned_variables(plan)
    nonce = secrets.token_hex(16)
    natives=planned_natives(plan)
    if natives:return decode(plan,nonce,owning_executor_capture(nonce,names,variables,natives))
    raw = (owning_executor_capture(nonce, names, variables) if variables
           else owning_executor_capture(nonce, names))
    return decode(plan, nonce, raw)
