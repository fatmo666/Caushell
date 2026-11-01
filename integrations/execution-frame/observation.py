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
