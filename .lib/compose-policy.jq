# =============================================================================
# compose-policy.jq — the compose policy's rules (.lib/compose-policy.sh runs it)
#
# Input: {"config": <the compose file as Compose resolves it>, "raw": <what .lib/compose-policy.py read from the file>}
# Arguments: $ctx {stack, stack_dir, base_dir}, $shipped / $local (slurped .config/compose-policy.json and
# .data/compose-policy.local.json), $extra (allow entries for this one call: a template's declared host access).
# Output: {"refused": [...], "warned": [...], "allowed": [...]}, each finding {rule, severity, service, image, message, line}.
#
# A finding's rule names exactly what it is about: "privileged", "cap:SYS_ADMIN", "pid:host", "network:host",
# "bind:/proc:ro", "bind:/var/run/docker.sock:rw", "device:/dev/sda", "security_opt:seccomp=unconfined",
# "sysctl:kernel.shmmax", "include:outside", ... An allow entry names rules (* matches anything) for an image or a stack.
# =============================================================================

def policy: (($shipped[0] // {}) as $s | ($local[0] // {}) as $l
    | {allow: (($s.allow // []) + ($l.allow // []) + ($extra // [])),
       devices: {warn: (($s.devices.warn // []) + ($l.devices.warn // [])),
                 ignore: (($s.devices.ignore // []) + ($l.devices.ignore // []))}});

# /a//b/./c/../d/ -> /a/b/d
def normpath:
    if type != "string" then . else
    (startswith("/")) as $abs
    | reduce (split("/")[] | select(. != "" and . != ".")) as $p ([];
        if $p == ".." then (if length > 0 then .[:-1] else . end) else . + [$p] end)
    | (if $abs then "/" else "" end) + join("/") end;

def under($b): . == $b or startswith(if $b == "/" then "/" else $b + "/" end);
def glob($g): . as $s | ($g | gsub("(?<c>[.+?^${}()|\\[\\]\\\\])"; "\\\(.c)") | gsub("\\*"; ".*")) as $re | ($s | test("^" + $re + "$"));
def truthy: . == true or ((type == "string") and (ascii_downcase | IN("true", "yes", "on", "1")));
def mode($ro): if $ro then "ro" else "rw" end;

# docker.io/library/nginx:1 -> nginx:1 ; the prefix of an allow entry matches the image or the image with a tag/digest
def normimage: (. // "") | tostring | ascii_downcase | sub("^(docker\\.io|index\\.docker\\.io|registry-1\\.docker\\.io)/"; "") | sub("^library/"; "");
def image_matches($prefix): ($prefix | normimage) as $p | normimage as $i
    | $p != "" and ($i == $p or ($i | startswith($p)) and (($p | test("[:@/]$")) or (($i[($p | length):] | .[0:1]) | IN(":", "@"))));

def finding($sev; $rule; $svc; $key; $msg):
    {severity: $sev, rule: $rule, service: $svc, key: $key, message: $msg};

# ---- from here on the input is at hand: $raw (what the file says), $cfg (what Compose makes of it) ------------
.raw as $raw | (.config // {}) as $cfg |

def real: (. as $p | ($raw.realpath[$p] // $p)) | normpath;

# ---- host paths: what a bind mount (or a named volume that is a bind) reaches --------------------------------
def harmless_etc: ["/etc/localtime", "/etc/timezone", "/etc/hostname", "/etc/machine-id", "/etc/os-release", "/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs", "/etc/ca-certificates", "/etc/pki/ca-trust", "/etc/pki/tls/certs"];
def socket_dirs: ["/run", "/var/run", "/run/docker", "/var/run/docker", "/run/containerd", "/var/run/containerd", "/run/podman", "/var/run/podman"];

def device_findings($p; $svc; $key):
    (policy.devices) as $d
    | if ($d.ignore | any(. as $g | $p | glob($g))) then empty
      elif $p == "/dev" then finding("refused"; "device:/dev"; $svc; $key; "the whole of /dev is every disk and the machine's memory: name the one device the app needs")
      elif ($d.warn | any(. as $g | $p | glob($g))) then finding("warned"; "device:" + $p; $svc; $key; "the device \($p) is passed into the container")
      else finding("refused"; "device:" + $p; $svc; $key; "the device \($p) is not one a container usually needs (a disk, the machine's memory, a raw port): it can read or change the host underneath Docker. If the app really needs it, allow \"device:\($p)\" for its image in this server's compose policy (PUT /config/compose-policy)")
      end;

def bind_findings($src; $ro; $svc; $key):
    ($src | real) as $p | mode($ro) as $m | ($ctx.base_dir | normpath) as $base | ($ctx.stack_dir | normpath) as $sd
    | if $p == "/" then finding("refused"; "bind:/:" + $m; $svc; $key; "mounts the host's whole file system (/)" + (if $ro then ", read-only: every secret on the machine can be read" else ": the container can change anything on the host" end))
      elif $p == "/etc" then finding("refused"; "bind:/etc:" + $m; $svc; $key; "mounts the host's /etc (passwords, sudoers, cron, ssh): mount the one file the app needs, read-only")
      elif ($p | under("/etc")) then
          (if $ro or (harmless_etc | any(. as $h | $p | under($h))) then empty
           else finding("refused"; "bind:" + $p + ":rw"; $svc; $key; "\($p) of the host is mounted writable: a change there is a change to the host's configuration (mount it with :ro)") end)
      elif ($p | under("/proc")) then finding("refused"; "bind:" + $p + ":" + $m; $svc; $key; "\($p) is the kernel's view of every process on the host")
      elif $p == "/sys" or ($p | under("/sys")) and ($ro | not) then finding("refused"; "bind:" + $p + ":" + $m; $svc; $key; "\($p) is the kernel's own settings" + (if $ro then "" else ", writable" end))
      elif ($p | under("/sys")) then finding("warned"; "bind:" + $p + ":ro"; $svc; $key; "\($p) of the host is visible in the container (read-only)")
      elif ($p | under("/boot")) then finding("refused"; "bind:" + $p + ":" + $m; $svc; $key; "\($p) holds the host's kernel and boot loader")
      elif $p == "/dev" then finding("refused"; "bind:/dev:" + $m; $svc; $key; "the whole of /dev is every disk and the machine's memory: name the one device the app needs")
      elif ($p | under("/dev")) then device_findings($p; $svc; $key)
      elif ($p | test("(^|/)(docker|containerd|podman)\\.sock$")) or (socket_dirs | index($p)) or ($p | test("^/run/user/[0-9]+(/docker\\.sock)?$")) then
          (if $ro then finding("warned"; "docker-socket:ro"; $svc; $key; "the Docker socket (\($p)) is mounted read-only: :ro does not stop API calls through a socket, so the container can still start containers. The docker-socket-proxy template lets an app read only what it needs")
           else finding("refused"; "docker-socket:rw"; $svc; $key; "the Docker socket (\($p)) gives the container the Docker API, and with it the whole host: use the docker-socket-proxy template, or allow it for this image in this server's compose policy (PUT /config/compose-policy)") end)
      elif ($p | under("/var/lib/docker")) then
          (if $ro then finding("warned"; "bind:" + $p + ":ro"; $svc; $key; "Docker's own data (\($p)) is visible in the container (read-only)")
           else finding("refused"; "bind:" + $p + ":rw"; $svc; $key; "Docker's own data (\($p)) is writable in the container: every container and volume on the host can be changed") end)
      elif ($p | under("/root")) then finding("refused"; "bind:" + $p + ":" + $m; $svc; $key; "\($p) is the home of root (its ssh keys and shell start-up files)")
      elif ($p | test("^/home/[^/]+/\\.ssh(/|$)")) then finding("refused"; "bind:" + $p + ":" + $m; $svc; $key; "\($p) holds a user's ssh keys")
      elif $base != "" and $p == $base then finding("refused"; "bind:dcs:" + $m; $svc; $key; "mounts the DCS folder itself (\($p)): its accounts, secrets key and scripts")
      elif $base != "" and ($p | under($base)) then
          (if ($p | under($sd)) and $sd != $base then empty
           elif ($ctx.compose_dir // "") != "" and ($p | under($ctx.compose_dir | normpath)) and ($p != ($ctx.compose_dir | normpath)) then empty
           elif ($p | under($base + "/.templates")) and $ro then empty
           else finding("refused"; "bind:dcs:" + $m; $svc; $key; "\($p) is part of DCS itself (accounts, secrets, the scripts the server runs): a stack mounts its own folder under Stacks/") end)
      elif $base != "" and ($base | under($p)) then
          (if $ro then finding("warned"; "bind:" + $p + ":ro"; $svc; $key; "\($p) contains the DCS folder (\($base)): the container can read its accounts and secrets")
           else finding("refused"; "bind:" + $p + ":rw"; $svc; $key; "\($p) contains the DCS folder (\($base)): the container could change the scripts the DCS server runs") end)
      elif ($p | test("^/home(/[^/]+)?$")) and ($ro | not) then finding("warned"; "bind:" + $p + ":rw"; $svc; $key; "\($p) is mounted writable (users' ssh keys and shell start-up files are in there)")
      else empty end;

def outside($p): ($ctx.stack_dir | normpath) as $sd | ($p | real) as $r | ($r | under($sd) | not);

# ---- one service ------------------------------------------------------------------------------------------------
def service_findings($name; $s; $cfg):
    [
      (if ($s.privileged | truthy) then finding("refused"; "privileged"; $name; "privileged"; "privileged: true gives the container every device and capability of the host, with no isolation") else empty end),
      (($s.cap_add // []) | map(tostring | ascii_upcase | sub("^CAP_"; "")) | unique[] as $c
        | if ($c | IN("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "SYS_BOOT")) then
              finding("refused"; "cap:" + $c; $name; "cap_add"; "the capability \($c) is enough to take over the host" + (if $c == "ALL" then " (ALL is every capability, SYS_ADMIN included)" else "" end))
          elif ($c | IN("NET_ADMIN", "SYS_PTRACE", "BPF", "PERFMON", "MAC_ADMIN", "MAC_OVERRIDE", "SYSLOG")) then
              finding("warned"; "cap:" + $c; $name; "cap_add"; "the capability \($c) is added" + (if $c == "NET_ADMIN" then " (it can change the network of whatever namespace it shares)" else "" end))
          else empty end),
      (if (($s.pid // "") | tostring | ascii_downcase) == "host" then finding("refused"; "pid:host"; $name; "pid"; "pid: host shows the container every process of the host (and, with a capability, lets it step into them)") else empty end),
      (if (($s.ipc // "") | tostring | ascii_downcase) == "host" then finding("refused"; "ipc:host"; $name; "ipc"; "ipc: host shares the host's shared memory with the container") else empty end),
      (if (($s.cgroup // "") | tostring | ascii_downcase) == "host" then finding("refused"; "cgroup:host"; $name; "cgroup"; "cgroup: host gives the container the host's control groups") else empty end),
      (if (($s.userns_mode // "") | tostring | ascii_downcase) == "host" then finding("refused"; "userns:host"; $name; "userns_mode"; "userns_mode: host turns off user namespace remapping for the container") else empty end),
      (if (($s.network_mode // "") | tostring | ascii_downcase) == "host" then finding("warned"; "network:host"; $name; "network_mode"; "network_mode: host puts the container on the host's network: every port it opens is open on the machine, and the proxy network does not reach it") else empty end),
      (($s.security_opt // [])[] | tostring | ascii_downcase | sub("^(?<k>[a-z]+)[:=]"; "\(.k)=") as $o
        | if ($o | IN("seccomp=unconfined", "apparmor=unconfined", "systempaths=unconfined")) then
              finding("refused"; "security_opt:" + $o; $name; "security_opt"; "\($o) turns off a layer of the container's isolation")
          else empty end),
      (($s.volumes // [])[] | select(type == "object") as $v
        | if $v.type == "bind" and ($v.source | type) == "string" then bind_findings($v.source; ($v.read_only == true); $name; "volumes")
          elif $v.type == "volume" and ($v.source | type) == "string" then
              (($cfg.volumes // {})[$v.source] // {}) as $tv
              | (($tv.driver_opts // {}) | with_entries(.key |= ascii_downcase)) as $o
              | if ($o.device | type) == "string" and ((($o.o // "") | tostring | test("(^|,)r?bind(,|$)")) or (($o.type // "") == "none")) then
                    bind_findings($o.device; ($v.read_only == true) or ((($o.o // "") | tostring | test("(^|,)ro(,|$)"))); $name; "volumes")
                else empty end
          else empty end),
      (($s.devices // [])[] | (if type == "object" then .source else (tostring | split(":")[0]) end) as $src
        | select(($src | type) == "string" and $src != "") | device_findings($src | real; $name; "devices")),
      (($s.device_cgroup_rules // [])[] | tostring as $r
        | if ($r | test("^\\s*a\\b")) or ($r | test("^\\s*[bc]\\s+\\*:\\*")) then finding("refused"; "device_cgroup_rule:" + $r; $name; "device_cgroup_rules"; "the device rule \"\($r)\" lets the container use every device of that kind (with mknod: the host's disks)")
          else finding("warned"; "device_cgroup_rule:" + $r; $name; "device_cgroup_rules"; "the device rule \"\($r)\" lets the container use host devices") end),
      (($s.sysctls // {}) | if type == "object" then keys[] else (.[] | tostring | split("=")[0]) end | select(startswith("net.") | not)
        | finding("warned"; "sysctl:" + .; $name; "sysctls"; "the kernel setting \(.) is changed for the container")),
      (($s.build // null) | if type == "object" then
          ([.context] + ((.additional_contexts // {}) | if type == "object" then [.[]] else [] end))[]
          | select(type == "string" and startswith("/")) | select(outside(.))
          | finding("refused"; "build:outside"; $name; "build"; "the build context \(.) is outside the stack's folder: a build can read every file under it into an image")
        else empty end),
      ((($s.image // "") | tostring | ascii_downcase | test("socket-proxy")) and (((($s.environment // {}) | if type == "object" then .POST else null end) // "") | tostring | ascii_downcase | IN("1", "true", "yes"))
        | if . then finding("warned"; "socket-proxy:POST"; $name; "environment"; "the socket proxy lets the apps behind it change things (POST=1): they can start containers through it") else empty end),
      (($s.volumes_from // [])[] | tostring | select(startswith("container:"))
        | finding("warned"; "volumes_from:container"; $name; "volumes_from"; "takes the volumes of the container \(sub("^container:"; "")), which this file does not show"))
    ];

def file_findings($cfg):
    ( ($raw.include // [])[] | select(outside(.)) | finding("refused"; "include:outside"; null; "include"; "include: names \(.), outside the stack's folder: everything a compose file can do comes in with it, unseen") ),
    ( ($raw.extends_files // [])[] | select(outside(.path)) | finding("refused"; "extends:outside"; .service; "extends"; "extends: reads \(.path), outside the stack's folder") ),
    ( ($raw.env_files // [])[] | select(outside(.path)) | finding("refused"; "env_file:outside"; .service; "env_file"; "env_file: reads \(.path), outside the stack's folder, into the container") ),
    ( [($cfg.services // {})[] | ((.configs // []) + (.secrets // []))[] | if type == "object" then .source else . end] as $used
      | ("configs", "secrets") as $kind | (($cfg[$kind] // {}) | to_entries[])
      | select((.value | type) == "object" and (.value.file | type) == "string" and ($used | index(.key)))
      | select(outside(.value.file))
      | finding("refused"; "file:outside"; null; $kind; "the \($kind) entry \(.key) reads \(.value.file), outside the stack's folder") );

# ---- allow entries ----------------------------------------------------------------------------------------------
def entry_matches($e; $f):
    (($e.rules // []) | any(. as $g | $f.rule | glob($g)))
    and ((($e.service // null) == null) or ($f.service != null and ($f.service | glob($e.service))))
    and ( (($e.image // null) as $im | $im != null and ($f.image | image_matches($im)))
          or (($e.stack // null) != null and $e.stack == $ctx.stack)
          or (($e.image // null) == null and ($e.stack // null) == null and ($e.any // false) == true) );

def place($f):
    ([policy.allow[] | select(entry_matches(.; $f))] | first) as $e
    | if $e == null then $f
      elif $f.severity == "refused" then $f + {severity: "warned", allowed_by: ($e.reason // "allowed by the compose policy")}
      else $f + {severity: "allowed", allowed_by: ($e.reason // "allowed by the compose policy")} end;

[ (($cfg.services // {}) | to_entries[] | select(.value | type == "object") | .key as $n | .value as $s
      | service_findings($n; $s; $cfg)[] | . + {image: ($s.image // null)}),
    (file_findings($cfg) | . + {image: (if .service then (($cfg.services // {})[.service].image // null) else null end)}) ]
| map(place(.)
      | . + {line: (if .service then ($raw.lines[.service][.key] // $raw.lines[.service]["_"] // null) else ($raw.lines["_top"][.key] // null) end)})
| unique_by([.severity, .rule, .service, .message])
| {refused: map(select(.severity == "refused")), warned: map(select(.severity == "warned")), allowed: map(select(.severity == "allowed"))}
