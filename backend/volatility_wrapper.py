import os
import re
import logging
import json
import sys
import shutil
import platform
import threading
import tempfile
import lzma
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess

from backend.plugin_registry import PLUGIN_MAP, normalize_plugin_id
from backend.cache_paths import resolve_volatility_cache_dir

logger = logging.getLogger(__name__)


def _get_clean_python_env():
    env = os.environ.copy()
    for name in (
        'PYTHONHOME',
        'PYTHONPATH',
        'PYTHONNOUSERSITE',
        'PYTHONUSERBASE',
        'PYTHONSAFEPATH',
        'PYTHONEXECUTABLE',
        '__PYVENV_LAUNCHER__',
    ):
        env.pop(name, None)
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONUTF8'] = '1'
    env.pop('PYTHONLEGACYWINDOWSSTDIO', None)
    return env


def _get_safe_subprocess_cwd() -> str:
    try:
        home = Path.home()
        if home.is_dir() and os.access(str(home), os.R_OK | os.X_OK):
            return str(home)
    except (OSError, RuntimeError):
        pass
    return tempfile.gettempdir()


def get_short_path(path: str) -> str:
    if platform.system() != 'Windows':
        return path

    try:
        path.encode('ascii')
        return path
    except UnicodeEncodeError:
        pass  

    try:
        import ctypes
        from ctypes import wintypes

        GetShortPathNameW = ctypes.windll.kernel32.GetShortPathNameW
        GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        GetShortPathNameW.restype = wintypes.DWORD

        buffer_size = 260
        short_path = ctypes.create_unicode_buffer(buffer_size)

        result = GetShortPathNameW(path, short_path, buffer_size)

        if result > 0 and result < buffer_size:
            converted = short_path.value
            if converted != path and len(converted) <= len(path):
                logger.info(f"中文路径转换为短路径: {path} -> {converted}")
                return converted
            else:
                logger.warning(
                    f"路径包含非ASCII字符但无法转换为短路径名: {path}\n"
                    f"建议在管理员权限的命令提示符中运行: fsutil 8dot3name set 1"
                )
                return path
        else:
            logger.warning(f"获取短路径失败: {path}")
            return path
    except Exception as e:
        logger.warning(f"获取短路径异常: {e}")
        return path


class VolatilityWrapper:

    _export_locks_guard = threading.Lock()
    _export_locks: Dict[str, threading.Lock] = {}

    def __init__(self, image_path: str, os_type: str = None, python_path: str = None, symbols_dir: str = None, cache_path: str = None):
        self.image_path = image_path
        self.image_name = os.path.basename(image_path)
        self._image_info = None
        self._python_path = python_path
        try:
            self._cache_path = resolve_volatility_cache_dir(cache_path, create=bool(cache_path))
        except OSError as exc:
            logger.warning(f"自定义 Volatility 缓存目录不可用，回退默认目录: {exc}")
            self._cache_path = None
        if os_type:
            os_lower = os_type.lower()
            if os_lower == 'windows':
                self._detected_os = 'Windows'
            elif os_lower == 'linux':
                self._detected_os = 'Linux'
            elif os_lower in ('mac', 'macos', 'darwin'):
                self._detected_os = 'macOS'
            else:
                self._detected_os = None
        else:
            self._detected_os = None

        self._project_root = self._get_project_root()

        if symbols_dir:
            self._symbols_dir = Path(symbols_dir)
        else:
            self._symbols_dir = self._get_symbols_dir()

        self._plugins_dir = self._get_plugins_dir()

        config = self._load_config()
        settings = config.get('settings', {})
        custom_vol_set = settings.get('custom_vol_path')
        if custom_vol_set:
            self._vol_path = self._find_vol_command() or self._find_vol_for_python()
        else:
            self._vol_path = self._find_vol_for_python() or self._find_vol_command()

        self._process_lock = threading.Lock()
        self._active_processes = set()
        self._cancel_requested = False

        logger.info(f"项目根目录: {self._project_root}")

    def _get_subprocess_kwargs(self, **kwargs) -> Dict[str, Any]:
        import platform
        import os

        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        if kwargs.get('text'):
            kwargs.setdefault('encoding', 'utf-8')
            kwargs.setdefault('errors', 'replace')

        env = kwargs.get('env', os.environ.copy())
        env['SYSDINTERNALS_EULA'] = '1'
        env['PYTHONWARNINGS'] = 'ignore'
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        env.pop('PYTHONLEGACYWINDOWSSTDIO', None)
        kwargs['env'] = env

        return kwargs

    def _register_process(self, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_processes.add(process)

    def _unregister_process(self, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_processes.discard(process)

    def _terminate_process(self, process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            logger.warning("Volatility 进程未及时退出，强制结束")
            process.kill()
            process.wait(timeout=2)
        except Exception as e:
            logger.warning(f"终止 Volatility 进程失败: {e}")

    def cancel_current_processes(self) -> None:
        self._cancel_requested = True
        with self._process_lock:
            processes = list(self._active_processes)
        for process in processes:
            self._terminate_process(process)

    def _run_subprocess(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        timeout = kwargs.pop('timeout', None)
        check = kwargs.pop('check', False)
        capture_output = kwargs.pop('capture_output', False)
        if capture_output:
            kwargs.setdefault('stdout', subprocess.PIPE)
            kwargs.setdefault('stderr', subprocess.PIPE)

        process = subprocess.Popen(cmd, **kwargs)
        self._register_process(process)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self._terminate_process(process)
            stdout, stderr = process.communicate()
            exc.output = stdout
            exc.stderr = stderr
            raise
        finally:
            self._unregister_process(process)

        if self._cancel_requested:
            raise RuntimeError('Volatility execution cancelled')

        completed = subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                cmd,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return completed

    def _is_text_renderer_encoding_error(self, stderr: str) -> bool:
        if not stderr:
            return False
        lower = stderr.lower()
        return (
            'unicodeencodeerror' in lower
            and 'text_renderer.py' in lower
            and ('gbk' in lower or 'cp936' in lower or 'codec can' in lower)
        )

    def _insert_renderer_arg(self, cmd: List[str], plugin_name: str, renderer: str) -> List[str]:
        updated = list(cmd)
        try:
            plugin_index = updated.index(plugin_name)
        except ValueError:
            plugin_index = len(updated)
        if '-r' not in updated and '--renderer' not in updated:
            updated[plugin_index:plugin_index] = ['-r', renderer]
        return updated

    def _extract_json_payload(self, output: str) -> str:
        text = (output or '').strip()
        if not text:
            return ''
        starts = [idx for idx in (text.find('['), text.find('{')) if idx >= 0]
        if not starts:
            return ''
        start = min(starts)
        end = max(text.rfind(']'), text.rfind('}'))
        if end < start:
            return ''
        return text[start:end + 1]

    def _flatten_json_rows(self, data: Any) -> List[Any]:
        rows: List[Any] = []

        def visit(node: Any) -> None:
            if isinstance(node, list):
                if node and not any(isinstance(item, (dict, list)) for item in node):
                    rows.append(node)
                    return
                for item in node:
                    visit(item)
                return
            if not isinstance(node, dict):
                return

            if 'rows' in node and isinstance(node.get('rows'), list):
                visit(node.get('rows'))
                return
            if 'treegrid' in node:
                visit(node.get('treegrid'))
                return

            rows.append(node)
            children = node.get('__children') or node.get('children')
            if children:
                visit(children)

        visit(data)
        return rows

    def _parse_json_filescan_rows(self, output: str, plugin_name: str) -> List[Dict]:
        payload = self._extract_json_payload(output)
        if not payload:
            return []
        try:
            data = json.loads(payload)
        except Exception as e:
            logger.warning(f"解析 JSON renderer 输出失败: {e}")
            return []

        results: List[Dict] = []
        for row in self._flatten_json_rows(data):
            if isinstance(row, list):
                row = {
                    'Offset': row[0] if len(row) > 0 else '',
                    'Name': row[1] if len(row) > 1 else '',
                }
            if not isinstance(row, dict):
                continue

            values = row.get('values')
            if isinstance(values, dict):
                row = values
            elif isinstance(values, list):
                row = {
                    'Offset': values[0] if len(values) > 0 else '',
                    'Name': values[1] if len(values) > 1 else '',
                }

            def cell_value(value: Any) -> Any:
                if isinstance(value, dict):
                    for key in ('value', 'Value', 'text', 'Text', 'repr', 'Repr'):
                        if key in value:
                            return value.get(key)
                    return ''
                return value

            offset = (
                row.get('Offset')
                or row.get('Offset(V)')
                or row.get('offset')
                or row.get('File Offset')
                or row.get('FileObject')
                or ''
            )
            name = (
                row.get('Name')
                or row.get('name')
                or row.get('Path')
                or row.get('path')
                or row.get('FileName')
                or row.get('File Name')
                or ''
            )
            offset = cell_value(offset)
            name = cell_value(name)

            if isinstance(offset, int):
                offset = hex(offset)
            else:
                offset = str(offset or '')

            if not offset or offset[0].lower() not in '0123456789abcdef':
                continue

            file_path = self._clean_string(str(name or ''))
            results.append({
                'offset': offset,
                'file_name': file_path,
                'path': file_path,
                'size': 0,
                'number_of_links': 0,
            })

        logger.info(f"JSON renderer 解析 {plugin_name} 结果: {len(results)} 条记录")
        return results

    def _retry_with_json_renderer(
        self,
        cmd: List[str],
        plugin_name: str,
        env: Dict[str, str],
        timeout: int = 300,
    ) -> Optional[List[Dict]]:
        if 'filescan' not in plugin_name.lower():
            return None

        json_cmd = self._insert_renderer_arg(cmd, plugin_name, 'json')
        logger.info(f"文本渲染编码失败，改用 JSON renderer 重试: {' '.join(json_cmd)}")
        subprocess_kwargs = self._get_subprocess_kwargs(
            env=env,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            check=False,
        )
        result = self._run_subprocess(json_cmd, **subprocess_kwargs)
        if result.returncode != 0:
            logger.warning(f"JSON renderer 重试失败: {result.stderr[:500] if result.stderr else 'unknown'}")
            return None
        parsed = self._parse_json_filescan_rows(result.stdout, plugin_name)
        return parsed if parsed else None

    def _is_windows_netstat_tcpip_symbol_error(self, plugin_name: str, stderr: str) -> bool:
        if not stderr:
            return False
        lower = stderr.lower()
        return (
            'windows.netstat' in plugin_name.lower()
            and 'tcpip' in lower
            and (
                'unable to locate symbols' in lower
                or 'required symbol library path not found' in lower
                or 'cannot write downloaded symbols' in lower
                or 'symbol file could not be downloaded' in lower
            )
        )

    def _extract_windows_pdb_request(self, stderr: str, default_pdb: str = 'tcpip.pdb') -> Optional[Dict[str, str]]:
        if not stderr:
            return None

        found_match = re.search(
            r'Found\s+([A-Za-z0-9_.-]+\.pdb):\s*([A-Fa-f0-9]{32})-(\d+)',
            stderr,
        )
        if found_match:
            return {
                'pdb_name': found_match.group(1),
                'guid': found_match.group(2).upper(),
                'age': found_match.group(3),
            }

        command_match = re.search(
            r'pdbconv\.py\s+-p\s+([A-Za-z0-9_.-]+\.pdb)\s+-g\s+([A-Fa-f0-9]{32})(\d+)',
            stderr,
        )
        if command_match:
            return {
                'pdb_name': command_match.group(1),
                'guid': command_match.group(2).upper(),
                'age': command_match.group(3),
            }

        guid_match = re.search(r'([A-Fa-f0-9]{32})-(\d+)', stderr)
        if guid_match:
            return {
                'pdb_name': default_pdb,
                'guid': guid_match.group(1).upper(),
                'age': guid_match.group(2),
            }

        guid_age_match = re.search(r'([A-Fa-f0-9]{32})(\d+)', stderr)
        if guid_age_match:
            return {
                'pdb_name': default_pdb,
                'guid': guid_age_match.group(1).upper(),
                'age': guid_age_match.group(2),
            }

        return None

    def _pdbconv_python_candidates(self) -> List[str]:
        candidates: List[str] = []

        def add(candidate: Optional[str]) -> None:
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        add(self._python_path)

        vol_path = Path(self._vol_path) if self._vol_path else None
        if vol_path and vol_path.exists():
            parent = vol_path.parent
            if platform.system() == 'Windows':
                add(str(parent / 'python.exe'))
                if parent.name.lower() == 'scripts':
                    add(str(parent.parent / 'python.exe'))
            else:
                add(str(parent / 'python3'))
                add(str(parent / 'python3.12'))
                add(str(parent / 'python3.11'))
                add(str(parent / 'python'))

        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and str(sys.argv[0]).endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka
        if not is_frozen:
            add(sys.executable)

        for name in ('python3', 'python', 'py'):
            add(shutil.which(name))

        existing = []
        for candidate in candidates:
            if candidate in ('python3', 'python', 'py') or Path(candidate).exists():
                existing.append(candidate)
        return existing

    def _fix_windows_pdb_metadata(self, symbol_file: Path, pdb_name: str, guid: str, age: str) -> bool:
        try:
            if symbol_file.suffix == '.xz':
                with lzma.open(symbol_file, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(symbol_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            metadata = data.setdefault('metadata', {})
            windows_meta = metadata.setdefault('windows', {})
            pdb_meta = windows_meta.setdefault('pdb', {})
            changed = False
            expected = {
                'GUID': guid.upper(),
                'age': int(age) if str(age).isdigit() else age,
                'database': pdb_name,
            }
            for key, value in expected.items():
                if pdb_meta.get(key) != value:
                    pdb_meta[key] = value
                    changed = True

            if changed:
                if symbol_file.suffix == '.xz':
                    with lzma.open(symbol_file, 'wt', encoding='utf-8') as f:
                        json.dump(data, f, separators=(',', ':'))
                else:
                    with open(symbol_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, separators=(',', ':'))
            return True
        except Exception as e:
            logger.warning(f"修正 PDB 符号 metadata 失败 {symbol_file}: {e}")
            return False

    def _convert_windows_pdb_symbol_in_process(
        self,
        pdb_name: str,
        guid: str,
        age: str,
        target_file: Path,
    ) -> bool:
        try:
            from urllib import parse, request
            from volatility3.framework import contexts
            from volatility3.framework.symbols.windows import pdbconv
        except Exception as e:
            logger.warning(f"当前进程不可用 pdbconv，无法内置转换模块符号: {e}")
            return False

        guid_age = f'{guid}{age}'

        def progress_callback(progress: float, description: Optional[str] = None) -> None:
            if progress >= 100 or int(progress) % 20 == 0:
                logger.debug(f"pdbconv 内置转换进度 {progress:.1f}% {description or ''}")

        temp_file = target_file.with_name(
            f'.{target_file.stem}.{os.getpid()}.{threading.get_ident()}.tmp{target_file.suffix}'
        )
        try:
            logger.info(f"使用内置 pdbconv 下载并转换 Windows 模块符号: {pdb_name} {guid}-{age}")
            filename = pdbconv.PdbRetreiver().retreive_pdb(
                guid=guid_age,
                file_name=pdb_name,
                progress_callback=progress_callback,
            )
            if not filename:
                logger.warning(f"内置 pdbconv 未能从 Microsoft Symbols 获取 {pdb_name} {guid}-{age}")
                return False

            url = parse.urlparse(filename, scheme='file')
            if url.scheme == 'file':
                if not os.path.exists(filename):
                    logger.warning(f"内置 pdbconv 下载的 PDB 文件不存在: {filename}")
                    return False
                location = 'file:' + request.pathname2url(os.path.abspath(filename))
            else:
                location = filename

            context = contexts.Context()
            convertor = pdbconv.PdbReader(
                context,
                location,
                database_name=pdb_name,
                progress_callback=progress_callback,
            )
            converted_json = convertor.get_json()
            with lzma.open(temp_file, 'wt', encoding='latin-1') as f:
                json.dump(converted_json, f, indent=2, sort_keys=True)

            if not self._fix_windows_pdb_metadata(temp_file, pdb_name, guid, age):
                return False
            shutil.move(str(temp_file), str(target_file))
            logger.info(f"Windows 模块符号已通过内置 pdbconv 安装: {target_file}")
            return True
        except Exception as e:
            logger.warning(f"内置 pdbconv 转换模块符号失败: {e}")
            return False
        finally:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception:
                pass

    def _ensure_windows_pdb_symbol(self, pdb_name: str, guid: str, age: str) -> bool:
        pdb_name = pdb_name.strip()
        guid = guid.strip().upper()
        age = str(age).strip()
        if not pdb_name or not guid or not age:
            return False

        target_dir = self._symbols_dir / 'windows' / pdb_name
        target_file = target_dir / f'{guid}-{age}.json.xz'
        if target_file.exists():
            logger.info(f"模块符号已存在: {target_file}")
            return self._fix_windows_pdb_metadata(target_file, pdb_name, guid, age)

        target_dir.mkdir(parents=True, exist_ok=True)
        guid_age = f'{guid}{age}'
        env = _get_clean_python_env()
        last_error = ''
        for python_cmd in self._pdbconv_python_candidates():
            fd, temp_name = tempfile.mkstemp(
                prefix=f'{pdb_name}_{guid}-{age}_',
                suffix='.json.xz',
                dir=str(target_dir),
            )
            os.close(fd)
            temp_file = Path(temp_name)
            try:
                cmd = [
                    python_cmd,
                    '-m',
                    'volatility3.framework.symbols.windows.pdbconv',
                    '-p',
                    pdb_name,
                    '-g',
                    guid_age,
                    '-o',
                    str(temp_file),
                ]
                logger.info(f"自动下载并转换 Windows 模块符号: {pdb_name} {guid}-{age}")
                kwargs = self._get_subprocess_kwargs(
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=600,
                    check=False,
                )
                result = self._run_subprocess(cmd, **kwargs)
                if result.returncode == 0 and temp_file.exists() and temp_file.stat().st_size > 0:
                    if not self._fix_windows_pdb_metadata(temp_file, pdb_name, guid, age):
                        last_error = 'metadata 修正失败'
                        continue
                    shutil.move(str(temp_file), str(target_file))
                    logger.info(f"Windows 模块符号已安装: {target_file}")
                    return True
                last_error = (result.stderr or result.stdout or '').strip()[-800:]
                logger.warning(f"pdbconv 自动转换失败 ({python_cmd}): {last_error}")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"pdbconv 执行异常 ({python_cmd}): {e}")
            finally:
                try:
                    if temp_file.exists():
                        temp_file.unlink()
                except Exception:
                    pass

        if self._convert_windows_pdb_symbol_in_process(pdb_name, guid, age, target_file):
            return True

        logger.warning(f"自动安装 Windows 模块符号失败: {pdb_name} {guid}-{age}; {last_error}")
        return False

    def _retry_netstat_after_tcpip_symbol_install(
        self,
        cmd: List[str],
        plugin_name: str,
        stderr: str,
        env: Dict[str, str],
        timeout: int = 300,
    ) -> Optional[List[Dict]]:
        if not self._is_windows_netstat_tcpip_symbol_error(plugin_name, stderr):
            return None

        pdb_info = self._extract_windows_pdb_request(stderr, 'tcpip.pdb')
        if not pdb_info:
            logger.warning("netstat 缺 tcpip 符号，但无法从日志提取 PDB GUID")
            return None

        if not self._ensure_windows_pdb_symbol(
            pdb_info['pdb_name'],
            pdb_info['guid'],
            pdb_info['age'],
        ):
            return None

        retry_cmd = list(cmd)
        if '-s' not in retry_cmd and '--symbol-dirs' not in retry_cmd and '--symbols' not in retry_cmd:
            try:
                plugin_index = retry_cmd.index(plugin_name)
            except ValueError:
                plugin_index = len(retry_cmd)
            retry_cmd[plugin_index:plugin_index] = ['-s', str(self._symbols_dir)]

        if platform.system() == 'Windows':
            retry_cmd = [
                get_short_path(arg) if isinstance(arg, str) and ('\\' in arg or '/' in arg) else arg
                for arg in retry_cmd
            ]

        logger.info(f"tcpip.pdb 模块符号安装完成，重跑 netstat: {' '.join(retry_cmd)}")
        kwargs = self._get_subprocess_kwargs(
            env=env,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            check=False,
        )
        result = self._run_subprocess(retry_cmd, **kwargs)
        if result.returncode == 0:
            parsed = self._parse_text_output(result.stdout, plugin_name)
            if parsed:
                return parsed
            if self._is_windows_netstat_tcpip_symbol_error(plugin_name, result.stderr or ''):
                logger.warning("netstat 重跑后仍提示 tcpip 符号缺失")
                return None
            return parsed

        logger.warning(f"netstat 安装 tcpip 符号后重跑失败: {result.stderr[:800] if result.stderr else 'unknown'}")
        return None

    def _windows_module_symbol_error(self, plugin_name: str, stderr: str) -> List[Dict]:
        pdb_info = self._extract_windows_pdb_request(stderr, 'tcpip.pdb') or {}
        pdb_name = pdb_info.get('pdb_name') or 'tcpip.pdb'
        guid = pdb_info.get('guid') or '未知GUID'
        age = pdb_info.get('age') or '未知age'
        return [{
            '_error': 'module_symbol_not_found',
            '_message': (
                f'{plugin_name} 需要 Windows 模块符号 {pdb_name} ({guid}-{age}) 才能恢复网络连接。'
                '工具已尝试自动下载/转换，但当前环境未成功。\n\n'
                '请确认网络可访问 Microsoft Symbols 后重试，或手动安装该 PDB 对应的 Volatility ISF 符号。'
            ),
            '_pdb_name': pdb_name,
            '_pdb_guid': guid,
            '_pdb_age': age,
        }]

    @staticmethod
    def _get_project_root() -> Path:
        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka

        if is_frozen:
            exe_path = Path(sys.argv[0]).resolve()
            if exe_path.is_file():
                return exe_path.parent
            else:
                return exe_path
        else:
            return Path(__file__).parent.parent

    def _load_config(self) -> dict:
        import platform as _platform
        system = _platform.system()

        if system == 'Windows':
            config_dir = Path('C:\\LensAnalysis')
        elif system == 'Darwin':
            config_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        else:
            config_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

        config_path = config_dir / 'config.json'
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass

        fallback = self._get_project_root() / 'data' / 'config.json'
        if fallback.exists():
            try:
                with open(fallback, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _find_vol_via_python(self) -> Optional[str]:
        for python_name in ['python', 'python3', 'py']:
            python_path = shutil.which(python_name)
            if not python_path:
                continue

            python_dir = Path(python_path).parent
            logger.info(f"Windows: 找到 {python_name} -> {python_path}")

            vol_exe = python_dir / 'Scripts' / 'vol.exe'
            if vol_exe.exists():
                logger.info(f"Windows: 从 Python 环境 Scripts 入口目录找到 vol: {vol_exe} (Python: {python_path})")
                return str(vol_exe)

            vol_exe = python_dir / 'vol.exe'
            if vol_exe.exists():
                logger.info(f"Windows: 从 Python 环境同级入口目录找到 vol: {vol_exe} (Python: {python_path})")
                return str(vol_exe)

        logger.warning("Windows: 未通过 Python 解释器找到 vol.exe")
        return None

    def _find_vol_for_python(self) -> Optional[str]:
        if not self._python_path:
            return None

        if '/' not in self._python_path and '\\' not in self._python_path:
            return None

        import platform
        python_dir = Path(self._python_path).parent

        if platform.system() == 'Windows':
            candidates = [python_dir / 'Scripts' / 'vol.exe', python_dir / 'vol.exe']
        else:
            candidates = [python_dir / 'vol', python_dir / 'vol3']

        for candidate in candidates:
            if candidate.exists():
                logger.info(f"从 Python 环境的命令入口目录找到 vol: {candidate} (Python: {self._python_path})")
                return str(candidate)
        return None

    def _get_execution_python(self, is_frozen: bool = False) -> str:
        if self._python_path:
            return self._python_path
        if is_frozen:
            return shutil.which('python') or shutil.which('python3') or 'python'
        return sys.executable

    def _find_vol_command(self) -> str:
        config = self._load_config()
        settings = config.get('settings', {})

        custom_vol_path = settings.get('custom_vol_path')
        if custom_vol_path:
            vol_path = Path(custom_vol_path).expanduser()
            if vol_path.is_file() and os.access(vol_path, os.X_OK):
                logger.info(f"使用自定义 vol 路径: {vol_path}")
                return str(vol_path)
            logger.warning(f"自定义 vol 路径无效或不可执行: {custom_vol_path}")

        if settings.get('custom_python_path') and self._python_path:
            logger.info("自定义 Python 未找到匹配 vol，使用该 Python 的模块方式")
            return None

        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka

        is_windows = platform.system() == 'Windows'

        if is_windows:
            vol_path = self._find_vol_via_python()
            if vol_path:
                return vol_path

        if is_frozen:
            if not is_windows:
                vol_path = shutil.which('vol')
                if vol_path:
                    logger.info(f"打包环境: 找到系统 vol 命令: {vol_path}")
                    return vol_path

            try:
                import volatility3
                logger.info("打包环境: Volatility 3 已打包进可执行文件，将使用 python -m volatility3")
                return None  
            except ImportError:
                logger.warning("打包环境: Volatility 3 未打包，且未找到系统 vol 命令")
                logger.warning("请安装 Volatility 3: pip install volatility3==2.27.0")
                return 'vol'  

        if not is_windows:
            vol_path = shutil.which('vol')
            if vol_path:
                logger.info(f"找到 vol 命令: {vol_path}")
                return vol_path

            home = Path.home()
            possible_paths = [
                home / '.local' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.9' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.10' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.11' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.12' / 'bin' / 'vol',
                Path('/usr/local/bin/vol'),
                Path('/usr/bin/vol'),
            ]

            for path in possible_paths:
                if path.exists() and os.access(path, os.X_OK):
                    logger.info(f"找到 vol 命令: {path}")
                    return str(path)

        logger.warning("未找到 vol 命令的具体路径，将依赖系统 PATH")
        return 'vol'

    @staticmethod
    def _get_symbols_dir() -> Path:
        import platform
        import sys

        system = platform.system()

        try:
            import json as _json
            if system == 'Windows':
                _config_dir = Path('C:\\LensAnalysis')
            elif system == 'Darwin':
                _config_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
            else:
                _config_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'
            _config_path = _config_dir / 'config.json'
            if _config_path.exists():
                with open(_config_path, 'r', encoding='utf-8') as f:
                    _config = _json.load(f)
                custom_symbols = _config.get('settings', {}).get('custom_symbols_path')
                if custom_symbols:
                    custom_path = Path(custom_symbols)
                    if custom_path.is_dir():
                        logger.info(f"使用自定义符号表目录: {custom_path}")
                        return custom_path
        except Exception as e:
            logger.warning(f"读取自定义符号表目录配置失败: {e}")

        system = platform.system()

        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka

        if system == 'Windows':  
            if is_frozen:
                exe_path = Path(sys.argv[0]).resolve()
                exe_dir = exe_path.parent
                data_dir_conf = exe_dir / 'data_dir.conf'

                if data_dir_conf.exists():
                    try:
                        configured_dir = data_dir_conf.read_text().strip()
                        if Path(configured_dir).exists():
                            logger.info(f"使用安装程序配置的数据目录: {configured_dir}")
                            symbols_dir = Path(configured_dir) / 'symbols'
                            symbols_dir.mkdir(parents=True, exist_ok=True)
                            return symbols_dir
                    except Exception as e:
                        logger.warning(f"读取 data_dir.conf 失败: {e}")

                base_dir = exe_dir / 'data'
            else:
                base_dir = Path(__file__).parent.parent / 'data'

            try:
                symbols_dir = base_dir / 'symbols'
                symbols_dir.mkdir(parents=True, exist_ok=True)
                test_file = symbols_dir / '.write_test'
                test_file.touch()
                test_file.unlink()
                return symbols_dir
            except (OSError, PermissionError):
                base_dir = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
                symbols_dir = base_dir / 'symbols'
                symbols_dir.mkdir(parents=True, exist_ok=True)
                return symbols_dir
        elif system == 'Darwin':  
            base_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        else:  
            base_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

        symbols_dir = base_dir / 'symbols'
        symbols_dir.mkdir(parents=True, exist_ok=True)

        return symbols_dir  

    @staticmethod
    def _get_plugins_dir() -> Path:
        import platform
        import sys

        system = platform.system()
        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka

        if system == 'Windows':
            if is_frozen:
                exe_path = Path(sys.argv[0]).resolve()
                exe_dir = exe_path.parent
                data_dir_conf = exe_dir / 'data_dir.conf'
                if data_dir_conf.exists():
                    try:
                        configured_dir = data_dir_conf.read_text().strip()
                        if Path(configured_dir).exists():
                            plugins_dir = Path(configured_dir) / 'plugins'
                            plugins_dir.mkdir(parents=True, exist_ok=True)
                            return plugins_dir
                    except Exception as e:
                        logger.warning(f"读取 data_dir.conf 失败: {e}")
                base_dir = exe_dir / 'data'
            else:
                base_dir = Path(__file__).parent.parent / 'data'
            try:
                plugins_dir = base_dir / 'plugins'
                plugins_dir.mkdir(parents=True, exist_ok=True)
                test_file = plugins_dir / '.write_test'
                test_file.touch()
                test_file.unlink()
                return plugins_dir
            except (OSError, PermissionError):
                base_dir = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
        elif system == 'Darwin':
            base_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        else:
            base_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

        plugins_dir = base_dir / 'plugins'
        plugins_dir.mkdir(parents=True, exist_ok=True)
        return plugins_dir

    @staticmethod
    def _get_volatility_cache_dirs() -> List[Path]:
        dirs = []
        system = platform.system()

        if system == 'Windows':
            appdata = os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')
            dirs.append(Path(appdata) / 'volatility3' / 'symbols')
            localappdata = os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')
            dirs.append(Path(localappdata) / 'volatility3' / 'symbols')
        else:
            cache_base = os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')
            dirs.append(Path(cache_base) / 'volatility3' / 'symbols')

        try:
            import volatility3
            vol_pkg_dir = Path(volatility3.__file__).parent
            dirs.append(vol_pkg_dir / 'symbols')
        except (ImportError, AttributeError):
            pass

        return dirs

    @staticmethod
    def migrate_volatility_symbols(symbols_dir: Path) -> int:
        migrated = 0

        for cache_dir in VolatilityWrapper._get_volatility_cache_dirs():
            if not cache_dir.exists():
                continue

            logger.info(f"扫描 Volatility 缓存目录: {cache_dir}")

            for symbol_file in cache_dir.rglob('*.json.xz'):
                try:
                    rel_path = symbol_file.relative_to(cache_dir)
                    dest_file = symbols_dir / rel_path

                    if dest_file.exists():
                        continue

                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(symbol_file), str(dest_file))
                    migrated += 1
                    logger.info(f"迁移符号表: {rel_path}")

                except Exception as e:
                    logger.warning(f"迁移符号表失败 {symbol_file}: {e}")

        if migrated > 0:
            logger.info(f"共迁移 {migrated} 个符号表文件到 {symbols_dir}")

        return migrated

    @staticmethod
    def _execution_failure_result(plugin_name: str, detail: str, error_type: str = 'volatility_error') -> List[Dict]:
        detail = str(detail or '').strip()
        detail_lower = detail.lower()
        if 'unable to open database file' in detail_lower or 'identifier.cache' in detail_lower:
            message = (
                'Volatility 无法打开缓存数据库。请确认所选缓存目录存在且可写，'
                '然后重试。LensAnalysis 会把该目录直接传给 --cache-path，'
                'identifier.cache 文件由 Volatility 自动管理。'
            )
        else:
            message = f'Volatility 插件执行失败：{plugin_name}'
        if detail:
            message = f'{message}\n\n{detail[-2000:]}'
        return [{'_error': error_type, '_message': message}]

    def _run_volatility(self, plugin_name: str, extra_args: List[str] = None, use_custom_plugins: bool = True, use_symbols: bool = True, symbol_file_path: str = None) -> List[Dict]:
        try:
            vol_path = self._vol_path

            import os
            env = _get_clean_python_env()

            env['VOLATILITY_SYMBOLS'] = str(self._symbols_dir)
            logger.info(f"设置符号表目录环境变量: VOLATILITY_SYMBOLS={self._symbols_dir}")

            env['PYTHONIOENCODING'] = 'utf-8'

            is_nuitka = hasattr(sys, 'nuitka_version') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
            )
            is_frozen = getattr(sys, 'frozen', False) or is_nuitka

            needs_custom_plugins = (
                'pypykatz_plugin.PypykatzPlugin' in plugin_name or
                'pypykatz' in plugin_name
            )

            if vol_path:
                cmd = [
                    vol_path,
                    '-f', self.image_path,
                ]
                logger.info(f"使用 vol 命令: {vol_path}")
            else:
                python_exe = self._get_execution_python(is_frozen)
                cmd = [
                    python_exe, '-m', 'volatility3',
                    '-f', self.image_path,
                ]
                logger.info(f"使用 python -m volatility3")

            if self._cache_path:
                cmd.extend(['--cache-path', str(self._cache_path)])
                logger.info(f"使用自定义缓存目录: {self._cache_path}")

            if use_custom_plugins and needs_custom_plugins:
                plugins_dir = str(self._plugins_dir)
                cmd.extend(['-p', plugins_dir])
                logger.info(f"使用自定义插件目录: {plugins_dir}")

            logger.info(f"DEBUG _run_volatility: symbol_file_path={symbol_file_path}, use_symbols={use_symbols}")
            if symbol_file_path and os.path.exists(str(symbol_file_path)):
                symbol_file = Path(symbol_file_path)

                parts = symbol_file.parts
                try:
                    symbols_idx = len(parts) - 1 - parts[::-1].index('symbols')
                    symbol_dir = Path(*parts[:symbols_idx + 1])
                except ValueError:
                    symbol_dir = self._symbols_dir

                cmd.extend(['-s', str(symbol_dir)])
                logger.info(f"使用指定符号表目录: {symbol_dir}")
            elif not use_symbols:
                logger.info("插件不需要符号表")
            else:
                logger.info(f"使用 Volatility 自动符号表下载（首次尝试）")


            if platform.system() == 'Windows':
                cmd = [get_short_path(arg) if isinstance(arg, str) and ('\\' in arg or '/' in arg) else arg
                       for arg in cmd]

            cmd.append(plugin_name)

            if extra_args:
                cmd.extend(extra_args)

            logger.info(f"执行命令: {' '.join(cmd)}")

            subprocess_kwargs = self._get_subprocess_kwargs(
                env=env,
                capture_output=True,
                text=True,
                encoding='utf-8',  
                errors='replace',  
                timeout=300,  
                check=False
            )
            result = self._run_subprocess(cmd, **subprocess_kwargs)

            netstat_tcpip_symbol_error = self._is_windows_netstat_tcpip_symbol_error(
                plugin_name,
                result.stderr or '',
            )
            netstat_retry = self._retry_netstat_after_tcpip_symbol_install(
                cmd,
                plugin_name,
                result.stderr or '',
                env,
                timeout=300,
            )
            if netstat_retry is not None:
                return netstat_retry
            if netstat_tcpip_symbol_error:
                return self._windows_module_symbol_error(plugin_name, result.stderr or '')

            if result.returncode != 0:
                error_output = result.stderr.lower()
                stdout_output = result.stdout.lower()

                if 'notimplementederror' in error_output or 'not supported' in error_output:
                    logger.error(f"插件不支持当前系统: {result.stderr}")
                    import re
                    version_match = re.search(r'(\d+\.\d+\s+\d+\.\d+)', result.stderr)
                    version_info = version_match.group(1) if version_match else '未知版本'
                    return [{
                        '_error': 'not_supported',
                        '_message': f'此插件不支持当前系统版本 ({version_info})。\n\n'
                                  f'这通常是 Volatility 3 框架的限制。\n'
                                  f'某些插件不支持旧版本的 Windows（如 Windows 7）。\n\n'
                                  f'建议：\n'
                                  f'• 尝试使用其他替代插件\n'
                                  f'• 对于命令历史，可尝试 cmdline 插件查看进程命令行参数'
                    }]

                symbol_errors = [
                    'unsatisfied requirement',
                    'symbol table',
                    'not found',
                    'cannot identify',
                    'no suitable',
                    'symbol table error',
                    'pdb signature not found',
                    'no pdb found'
                ]

                if any(err in error_output or err in stdout_output for err in symbol_errors):
                    if use_symbols and not any('-s' in str(arg) for arg in cmd) and not symbol_file_path:
                        logger.warning(f"官方符号表下载失败，尝试使用本地符号表...")
                        plugin_index = cmd.index(plugin_name)
                        cmd_with_symbols = (
                            cmd[:plugin_index]
                            + ['-s', str(self._symbols_dir)]
                            + cmd[plugin_index:]
                        )

                        if platform.system() == 'Windows':
                            cmd_with_symbols = [get_short_path(arg) if isinstance(arg, str) and ('\\' in arg or '/' in arg) else arg
                                                  for arg in cmd_with_symbols]

                        logger.info(f"重试命令: {' '.join(cmd_with_symbols)}")
                        subprocess_kwargs = self._get_subprocess_kwargs(
                            env=env,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            timeout=300,
                            check=False
                        )
                        result = self._run_subprocess(cmd_with_symbols, **subprocess_kwargs)

                        netstat_tcpip_symbol_error = self._is_windows_netstat_tcpip_symbol_error(
                            plugin_name,
                            result.stderr or '',
                        )
                        netstat_retry = self._retry_netstat_after_tcpip_symbol_install(
                            cmd_with_symbols,
                            plugin_name,
                            result.stderr or '',
                            env,
                            timeout=300,
                        )
                        if netstat_retry is not None:
                            return netstat_retry
                        if netstat_tcpip_symbol_error:
                            return self._windows_module_symbol_error(plugin_name, result.stderr or '')

                        stderr_lower = result.stderr.lower() if result.stderr else ''
                        has_symbol_error = any(err in stderr_lower for err in [
                            'no suitable symbol file',
                            'symbol file not found',
                            'cannot determine',
                            'failed to load symbol'
                        ])

                        if result.returncode != 0 and self._is_text_renderer_encoding_error(result.stderr or ''):
                            json_results = self._retry_with_json_renderer(cmd_with_symbols, plugin_name, env, timeout=300)
                            if json_results is not None:
                                logger.info("使用本地符号表 + JSON renderer 成功")
                                return json_results
                            return [{
                                '_error': 'output_encoding_error',
                                '_message': (
                                    'Volatility 在 Windows 文本输出阶段遇到无法编码的文件名字符，'
                                    '且 JSON renderer 重试失败。'
                                )
                            }]

                        if result.returncode == 0 or (result.stdout and not has_symbol_error):
                            logger.info("使用本地符号表成功")
                            return self._parse_text_output(result.stdout, plugin_name)
                        else:
                            logger.error(f"本地符号表也失败: {result.stderr[:500] if result.stderr else 'unknown'}")
                            return [{
                                '_error': 'symbol_not_found',
                                '_message': self._get_symbol_error_message(plugin_name)
                            }]
                    else:
                        stderr_lower = result.stderr.lower() if result.stderr else ''
                        has_symbol_error = any(err in stderr_lower for err in [
                            'no suitable symbol file',
                            'symbol file not found',
                            'cannot determine',
                            'failed to load symbol'
                        ])
                        if has_symbol_error:
                            logger.error(f"符号表错误: {result.stderr[:500]}")
                            return [{
                                '_error': 'symbol_not_found',
                                '_message': self._get_symbol_error_message(plugin_name)
                            }]

                logger.warning(f"Volatility 执行失败: {result.stderr}")

                stderr_text = result.stderr if result.stderr else ''
                stderr_lower = stderr_text.lower()

                if self._is_text_renderer_encoding_error(stderr_text):
                    json_results = self._retry_with_json_renderer(cmd, plugin_name, env, timeout=300)
                    if json_results is not None:
                        return json_results
                    return [{
                        '_error': 'output_encoding_error',
                        '_message': (
                            'Volatility 在 Windows 文本输出阶段遇到无法编码的文件名字符，'
                            '且 JSON renderer 重试失败。\n\n'
                            '这不是镜像路径或符号表问题；插件已经开始扫描，但文本表格渲染崩溃。\n'
                            '请清除该插件缓存后重试，或将日志发给开发者继续定位。'
                        )
                    }]

                if 'invalid choice' in stderr_lower:
                    import re
                    match = re.search(r'invalid choice\s+(\S+)', stderr_text)
                    invalid_plugin = match.group(1).lower() if match else ''

                    if 'pypykatz' in invalid_plugin:
                        error_msg = (
                            "明文密码提取需要 pypykatz 库支持。\n"
                            "请在命令行运行以下命令安装：\n"
                            "    pip install pypykatz\n"
                            "安装后重启工具即可使用明文密码提取功能。"
                        )
                        logger.error(f"pypykatz 插件不可用: {error_msg}")
                        return [{
                            '_error': 'pypykatz_missing',
                            '_message': error_msg
                        }]
                    elif any(p in invalid_plugin for p in ['hashdump', 'lsadump', 'cachedump']):
                        error_msg = (
                            "该插件需要 pycryptodome 库支持，但当前的 volatility3 环境未安装。\n"
                            "请在命令行运行以下命令安装：\n"
                            "    pip install pycryptodome\n"
                            "安装后重启工具即可使用该插件。"
                        )
                        logger.error(error_msg)
                        return [{
                            '_error': 'pycryptodome_missing',
                            '_message': error_msg
                        }]

                return self._execution_failure_result(
                    plugin_name,
                    result.stderr or result.stdout,
                )

            return self._parse_text_output(result.stdout, plugin_name)

        except subprocess.TimeoutExpired:
            logger.error(f"Volatility 执行超时: {plugin_name}")
            return self._execution_failure_result(
                plugin_name,
                '执行超过 300 秒，已终止。',
                error_type='timeout',
            )
        except RuntimeError as e:
            if 'cancelled' in str(e).lower():
                logger.info(f"Volatility 执行已取消: {plugin_name}")
                return [{
                    '_error': 'cancelled',
                    '_message': '插件执行已取消'
                }]
            raise
        except Exception as e:
            error_str = str(e)
            logger.error(f"Volatility 执行异常: {error_str}")

            if 'EOFError' in error_str or 'Compressed file ended' in error_str:
                logger.warning("检测到符号表文件损坏，尝试重新下载...")
                try:
                    import glob
                    for symbol_file in glob.glob(str(self._symbols_dir / '**/*.json.xz'), recursive=True):
                        try:
                            import lzma
                            with open(symbol_file, 'rb') as f:
                                with lzma.open(f) as zf:
                                    json.load(zf)
                        except:
                            logger.warning(f"删除损坏的符号表文件: {symbol_file}")
                            os.remove(symbol_file)
                except Exception as cleanup_error:
                    logger.warning(f"清理符号表时出错: {cleanup_error}")

                try:
                    logger.info(f"重新执行插件: {plugin_name}")
                    return self._run_volatility(plugin_name, extra_args, use_custom_plugins, use_symbols, symbol_file_path)
                except Exception as retry_error:
                    logger.error(f"重试失败: {retry_error}")

            return self._execution_failure_result(plugin_name, error_str)

    def _get_symbol_error_message(self, plugin_name: str) -> str:
        if 'linux' in plugin_name.lower() or '.mac' in plugin_name.lower():
            return (f"未找到匹配的符号表。\n\n"
                    f"此插件需要特定版本的符号表才能正常工作。\n"
                    f"请检查符号表管理器是否已安装对应的符号文件。\n\n"
                    f"提示：\n"
                    f"• Linux: 符号表必须与内核版本完全匹配\n"
                    f"• macOS: 符号表必须与系统版本匹配\n"
                    f"• 可以在工具栏点击「符号表」按钮管理符号文件")

        return "未找到匹配的符号表，请检查符号表是否已安装。"

    def _run_volatility_raw_result(
        self,
        plugin_name: str,
        extra_args: List[str] = None,
        use_symbols: bool = False,
        quiet: bool = False,
        output_dir: str = None,
        renderer: str = None,
    ) -> Dict[str, Any]:
        cmd = []
        try:
            if getattr(self, '_cancel_requested', False):
                return {
                    'status': 'cancelled',
                    'returncode': None,
                    'stdout': '',
                    'stderr': '',
                    'command': cmd,
                    'error': '用户已取消导出',
                }

            if output_dir:
                Path(output_dir).mkdir(parents=True, exist_ok=True)

            vol_path = self._vol_path

            is_nuitka = hasattr(sys, 'nuitka_version') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
            )
            is_frozen = getattr(sys, 'frozen', False) or is_nuitka

            if vol_path:
                cmd = [
                    vol_path,
                    '-f', self.image_path,
                ]
                if not quiet:
                    logger.info(f"使用 vol 命令: {vol_path}")
            else:
                python_exe = self._get_execution_python(is_frozen)
                cmd = [
                    python_exe, '-m', 'volatility3',
                    '-f', self.image_path,
                ]
                if not quiet:
                    logger.info("使用 python -m volatility3")

            if use_symbols:
                cmd.extend(['-s', str(self._symbols_dir)])

            if output_dir:
                cmd.extend(['-o', str(Path(output_dir).resolve())])

            if os.path.exists(self._plugins_dir):
                cmd.extend(['--plugin-dirs', str(self._plugins_dir)])

            if self._cache_path:
                cmd.extend(['--cache-path', str(self._cache_path)])

            if renderer:
                cmd.extend(['-r', str(renderer)])

            cmd.append(plugin_name)

            if extra_args:
                cmd.extend(extra_args)

            env = _get_clean_python_env()
            env['VOLATILITY_SYMBOLS'] = str(self._symbols_dir)
            if not quiet:
                logger.info(f"设置符号表目录环境变量: VOLATILITY_SYMBOLS={self._symbols_dir}")
                logger.info("执行导出命令: %s", subprocess.list2cmdline(cmd))

            env['PYTHONIOENCODING'] = 'utf-8'

            subprocess_kwargs = self._get_subprocess_kwargs(
                env=env,
                capture_output=True,
                text=True,
                encoding='utf-8',  
                errors='replace',  
                timeout=300,
                check=False
            )
            result = self._run_subprocess(cmd, **subprocess_kwargs)

            if result.returncode != 0:
                logger.error(f"Volatility 命令失败 (returncode={result.returncode}): {result.stderr[:500]}")
                return {
                    'status': 'error',
                    'returncode': result.returncode,
                    'stdout': result.stdout or '',
                    'stderr': result.stderr or '',
                    'command': cmd,
                    'error': (result.stderr or result.stdout or 'Volatility 命令执行失败').strip(),
                }

            return {
                'status': 'success',
                'returncode': result.returncode,
                'stdout': result.stdout or '',
                'stderr': result.stderr or '',
                'command': cmd,
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Volatility 执行超时: {plugin_name}")
            return {
                'status': 'timeout',
                'returncode': None,
                'stdout': '',
                'stderr': '',
                'command': cmd,
                'error': 'Volatility 执行超过 300 秒，已终止',
            }
        except RuntimeError as e:
            if 'cancelled' in str(e).lower():
                logger.info(f"Volatility 原始输出执行已取消: {plugin_name}")
                return {
                    'status': 'cancelled',
                    'returncode': None,
                    'stdout': '',
                    'stderr': '',
                    'command': cmd,
                    'error': '用户已取消导出',
                }
            raise
        except Exception as e:
            logger.error(f"Volatility 执行异常: {str(e)}")
            return {
                'status': 'error',
                'returncode': None,
                'stdout': '',
                'stderr': '',
                'command': cmd,
                'error': str(e),
            }

    def _run_volatility_raw(
        self,
        plugin_name: str,
        extra_args: List[str] = None,
        use_symbols: bool = False,
        quiet: bool = False,
    ) -> str:
        result = self._run_volatility_raw_result(
            plugin_name,
            extra_args,
            use_symbols=use_symbols,
            quiet=quiet,
        )
        return result.get('stdout', '')

    def _run_volatility_export(
        self,
        plugin_name: str,
        extra_args: List[str],
        output_dir: str,
        use_symbols: bool = True,
        renderer: str = None,
    ) -> Dict[str, Any]:
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        export_lock = self._get_export_lock(output_path)

        with export_lock:
            before = self._snapshot_output_files(output_path)
            run = self._run_volatility_raw_result(
                plugin_name,
                extra_args,
                use_symbols=use_symbols,
                output_dir=str(output_path),
                renderer=renderer,
            )

            produced = []
            if run.get('status') == 'success':
                after = self._snapshot_output_files(output_path)
                for name, fingerprint in after.items():
                    if before.get(name) != fingerprint:
                        produced.append(output_path / name)
                produced.sort(key=lambda item: item.stat().st_mtime_ns)

            return {'run': run, 'files': produced, 'output_dir': str(output_path)}

    @classmethod
    def _get_export_lock(cls, output_dir: Path) -> threading.Lock:
        key = os.path.normcase(str(Path(output_dir).resolve()))
        with cls._export_locks_guard:
            lock = cls._export_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._export_locks[key] = lock
            return lock

    @staticmethod
    def _snapshot_output_files(output_dir: Path) -> Dict[str, tuple]:
        snapshot = {}
        try:
            paths = list(output_dir.iterdir())
        except OSError:
            return snapshot

        for path in paths:
            try:
                if path.is_file():
                    stat = path.stat()
                    snapshot[path.name] = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                continue
        return snapshot

    @staticmethod
    def _unique_output_path(path: Path) -> Path:
        if not path.exists():
            return path
        counter = 1
        while True:
            candidate = path.with_name(f'{path.stem}-{counter}{path.suffix}')
            if not candidate.exists():
                return candidate
            counter += 1

    @staticmethod
    def _export_failure(run: Dict[str, Any], fallback: str) -> Dict[str, Any]:
        status = run.get('status', 'error')
        return {
            'status': status if status == 'cancelled' else 'failed',
            'error': run.get('error') or fallback,
            'returncode': run.get('returncode'),
            'stderr': run.get('stderr', ''),
        }

    def _format_size(self, size_bytes: int) -> str:
        if not size_bytes or size_bytes == 0:
            return '0 B'
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for i, unit in enumerate(units):
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    def _clean_string(self, s: str) -> str:
        if not s:
            return ''

        return ''.join(
            char if char.isprintable() and char != '\ufffd' else '?'
            for char in s
        )

    def _parse_text_output(self, output: str, plugin_name: str) -> List[Dict]:
        lines = output.strip().split('\n')
        if len(lines) < 3:
            logger.warning(f"{plugin_name} 输出少于3行: {len(lines)}行")
            if lines:
                logger.warning(f"前5行内容:\n" + "\n".join(lines[:5]))
            return []

        if 'printkey' in plugin_name.lower():
            logger.warning(f"printkey 原始输出:\n{output[:1500]}")

        if 'userassist' in plugin_name.lower():
            logger.warning(f"userassist 原始输出:\n{output[:3000]}")

        data_lines = []
        for line in lines:
            if not line.strip() or line.startswith('Progress'):
                continue
            is_header = self._is_header_row(line, plugin_name)
            if is_header:
                continue
            data_lines.append(line)

        if 'scheduled_tasks' in plugin_name:
            merged_lines = []
            for line in data_lines:
                if (line and line[0] in (' ', '\t') and line.strip()
                        and merged_lines and '\t' not in line):
                    merged_lines[-1] = merged_lines[-1].rstrip('\n') + ' ' + line.strip()
                else:
                    merged_lines.append(line)
            data_lines = merged_lines

        results = []
        for line in data_lines:
            stripped_line = line.strip()
            if self._is_hex_dump_line(stripped_line):
                continue

            if '\t' in line:
                parts = line.split('\t')
            else:
                parts = line.split()
                if len(parts) < 3:
                    parts = re.split(r'\s{2,}', line.strip())

            if parts and len(parts) >= 2:
                result = self._parse_plugin_result(plugin_name, parts)
                if result:
                    results.append(result)
                else:
                    logger.debug(f"解析失败: plugin={plugin_name}, parts={len(parts)}, first_3={parts[:3]}")

        logger.info(f"解析 {plugin_name} 结果: {len(results)} 条记录")
        logger.info(f"  共处理 {len(data_lines)} 行数据")

        if len(results) == 0 and len(data_lines) > 0:
            logger.warning(f"警告: {plugin_name} 有 {len(data_lines)} 行数据但解析出 0 条记录")
            for i, line in enumerate(data_lines[:5]):
                logger.warning(f"  数据行 {i+1}: {line[:100]}")

        return results

    def _is_hex_dump_line(self, line: str) -> bool:
        if not line:
            return False
        if '\t' in line:
            return False
        tokens = line.split()
        if len(tokens) < 4:
            return False
        hex_count = sum(
            1 for t in tokens
            if len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t)
        )
        return hex_count >= len(tokens) * 0.6

    def _is_header_row(self, line: str, plugin_name: str = '') -> bool:
        if not line.strip():
            return False
        if line.startswith('Progress'):
            return False

        stripped = line.strip()
        if all(c in ['-', '='] for c in stripped):
            return True

        if 'Volatility 3' in line:
            return True

        if 'Last Write Time' in line or 'Hive Offset' in line or 'Key Name' in line:
            return True

        if 'banner' in plugin_name.lower():
            if line.strip() == 'Offset\tBanner' or line.strip() == 'Offset Banner':
                return True

        if line.startswith('Offset') and 'FileFullPath' in line:
            return True

        if '\t' in line:
            parts = line.split('\t')
        else:
            parts = line.split()
            if len(parts) < 3:
                parts = re.split(r'\s{2,}', line.strip())

        first_part = parts[0].strip() if parts else ''
        if first_part.isdigit():
            return False

        if re.match(r'^\d{4}-\d{2}-\d{2}', first_part):
            return False

        if '\\' in first_part or '/' in first_part:
            return False

        if len(parts) > 0:
            first_part = parts[0].strip()
            if '.exe' in first_part.lower() or (any(c.islower() for c in first_part) and not first_part.startswith('0x')):
                return False

        header_keywords = [
            'PID', 'Process', 'Base', 'Offset', 'Name', 'Path', 'Size', 'Address', 'Time', 'Banner',
            'Device', 'Mount', 'Point', 'Type', 'Interface', 'IP', 'MAC', 'Promiscuous',
            'Function', 'Param', 'Deadline', 'Entry', 'Module', 'Symbol',
            'Proto', 'Local', 'Foreign', 'State', 'LAddr', 'LPort', 'RAddr', 'RPort',
            'Start', 'End', 'Protection', 'Map', 'File', 'output',
            'Ident', 'Filter', 'Context',
            'Index', 'IData', 'Callback', 'Listeners',
            'Socket', 'Member', 'Policy',
            'UID', 'GID', 'PPID', 'Argc', 'Arguments',
            'TID', 'VAD', 'VAD', 'Note',
            'Certificate', 'Section', 'ID',
            'Hive', 'Last', 'Write',
            'EPROCESS', 'SeAudit', 'ImageFileName', 'ImageFilePath', 'Spoofed', 'PEB',
            'PEB_ImageFilePath', 'PEB_CommandLine',
            'Distinct', 'Implementations', 'Different'
        ]

        if 'banner' in plugin_name.lower() and len(parts) >= 1:
            first_col = parts[0].strip()
            if first_col.startswith('0x'):
                return False  

        header_as_columns = sum(1 for keyword in header_keywords if any(keyword in part for part in parts))
        if header_as_columns >= 2:
            return True

        if 'printkey' in plugin_name:
            printkey_headers = ['Last', 'Write', 'Time', 'Hive', 'Offset', 'Type', 'Key', 'Name', 'Data', 'Volatile']
            matching_count = sum(1 for header in printkey_headers if header in line)
            if matching_count >= 4:  
                return True

        if len(parts) == 2:
            second_part = parts[1].strip()
            if 'banner' in plugin_name.lower():
                if parts[0].strip() == 'Offset' and second_part == 'Banner':
                    return True
                if parts[0].strip().startswith('0x'):
                    return False
            elif second_part in header_keywords:
                return True

        if len(parts) >= 3:
            header_style_count = 0
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if (any(c.isupper() for c in part) or ' ' in part) and not part.startswith('0x'):
                    header_style_count += 1
            if header_style_count >= len(parts) * 0.7:  
                return True

        return False

    def _parse_plugin_result(self, plugin_name: str, parts: List[str]) -> Optional[Dict]:

        if 'banner' in plugin_name.lower():
            if len(parts) >= 2:
                return {
                    'offset': str(parts[0]),
                    'banner': ' '.join(parts[1:])  
                }

        if ('pslist' in plugin_name or 'psscan' in plugin_name or 'pstree' in plugin_name) and 'windows.' in plugin_name.lower():
            if len(parts) >= 11:
                result = {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'name': str(parts[2]).strip() if len(parts) > 2 else '',
                    'threads': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'handles': int(parts[5]) if len(parts) > 5 and str(parts[5]).isdigit() else 0,
                    'session_id': str(parts[6]) if len(parts) > 6 else '0',
                    'create_time': str(parts[8]) if len(parts) > 8 else ''
                }
                if len(parts) > 3:
                    result['offset'] = str(parts[3])
                if len(parts) > 7:
                    result['wow64'] = str(parts[7])
                if len(parts) > 9:
                    result['exit_time'] = str(parts[9])
                if len(parts) > 11:
                    result['command_line'] = str(parts[11])
                return result

        elif 'cmdline' in plugin_name:
            if len(parts) >= 2:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'name': str(parts[1]).strip() if len(parts) > 1 else '',
                    'command_line': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        elif 'netscan' in plugin_name:
            if len(parts) >= 10:
                pid_str = str(parts[7]) if len(parts) > 7 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'protocol': str(parts[1]),
                    'local_address': str(parts[2]),
                    'local_port': str(parts[3]),
                    'remote_address': str(parts[4]),
                    'remote_port': str(parts[5]),
                    'state': str(parts[6]),
                    'pid': int(pid_str),
                    'process_name': str(parts[8]),
                    'create_time': str(parts[9]) if len(parts) > 9 else ''
                }

        elif 'filescan' in plugin_name:
            if len(parts) >= 2:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                file_path = self._clean_string(str(parts[1]))

                return {
                    'offset': offset,
                    'file_name': file_path,
                    'path': file_path,
                    'size': 0,
                    'number_of_links': 0
                }

        elif 'hivelist' in plugin_name:
            if len(parts) >= 2:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                file_path = str(parts[1]) if len(parts) > 1 and parts[1] else ''
                hive_status = str(parts[2]) if len(parts) > 2 else 'Unknown'

                if file_path:
                    name = file_path.split('\\')[-1]
                else:
                    name = 'Registry Root'
                    file_path = '\\REGISTRY\\MACHINE'

                if file_path and 'SYSTEM' in file_path.upper():
                    printkey_path = ''  
                elif file_path and 'SAM' in file_path.upper():
                    printkey_path = ''  
                elif file_path and 'SOFTWARE' in file_path.upper():
                    printkey_path = ''  
                elif file_path and 'SECURITY' in file_path.upper():
                    printkey_path = ''  
                else:
                    printkey_path = ''  

                return {
                    'offset': offset,
                    'name': name,
                    'path': file_path,
                    'hive_type': hive_status,
                    'printkey_path': printkey_path
                }

        elif 'certificates' in plugin_name:
            if len(parts) >= 4:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['certificate', 'path', 'section', 'id', 'name', 'key', 'hive']
                if first_col in header_keywords:
                    return None

                return {
                    'path': str(parts[0]),
                    'section': str(parts[1]),
                    'id': str(parts[2]),
                    'name': str(parts[3]) if len(parts) > 3 and parts[3] != '-' else '',
                    'hive': str(parts[0]).split('\\')[0] if '\\' in str(parts[0]) else str(parts[0])
                }

        elif 'unhooked_system_calls' in plugin_name:
            if len(parts) >= 3:
                function_name = str(parts[0])
                distinct_impl = str(parts[1])
                total_impl = str(parts[2]) if len(parts) > 2 else ''

                first_col = function_name.lower()
                header_keywords = ['function', 'distinct', 'implementations', 'total', 'unhooked', 'system', 'calls', 'nt']
                if first_col in header_keywords:
                    return None

                if distinct_impl.isdigit():
                    return {
                        'function': function_name,
                        'distinct_implementations': int(distinct_impl),
                        'total_implementations': int(total_impl) if total_impl.isdigit() else 0,
                        'different_processes': ''
                    }
                else:
                    return {
                        'function': function_name,
                        'distinct_implementations': len(distinct_impl.split(',')) if distinct_impl else 0,
                        'total_implementations': int(total_impl) if total_impl.isdigit() else 0,
                        'different_processes': distinct_impl
                    }

        elif 'pebmasquerade' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['offset', 'pid', 'eprocess', 'image', 'filename', 'seaudit', 'peb', 'masquerade', 'spoofed']
                if first_col in header_keywords:
                    return None

                return {
                    'offset': str(parts[0]) if not str(parts[0]).isdigit() else '',
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'eprocess_name': str(parts[1]) if len(parts) > 1 else '',
                    'seaudit_name': str(parts[2]) if len(parts) > 2 else '',
                    'peb_path': str(parts[3]) if len(parts) > 3 else '',
                    'path_spoofed': str(parts[4]) if len(parts) > 4 else '',
                    'cmdline_spoofed': str(parts[5]) if len(parts) > 5 else '',
                    'masqueraded': str(parts[4]) if len(parts) > 4 else ''  
                }

        elif 'malfind' in plugin_name and 'linux' not in plugin_name and 'mac' not in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'address': str(parts[2]) if len(parts) > 2 else '',
                    'size': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'protection': str(parts[4]) if len(parts) > 4 else '',
                    'suspicious': True,
                    'reason': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'dlllist' in plugin_name:
            if len(parts) >= 5:
                header_keywords = ['base', 'size', 'name', 'path', 'loadtime', 'pid', 'process']
                first_col = str(parts[0]).lower() if parts[0] else ''
                if first_col in header_keywords:
                    return None

                if str(parts[0]).isdigit() and len(parts) >= 7:
                    return {
                        'pid': int(parts[0]),
                        'process_name': str(parts[1]),
                        'base_address': str(parts[2]),
                        'size': str(parts[3]),
                        'name': str(parts[4]),
                        'path': str(parts[5]),
                        'load_time': str(parts[6]) if len(parts) > 6 else ''
                    }
                elif not str(parts[0]).isdigit():
                    return {
                        'pid': 0,  
                        'process_name': '',
                        'base_address': str(parts[0]),
                        'size': str(parts[1]),
                        'name': str(parts[2]),
                        'path': str(parts[3]),
                        'load_time': str(parts[4]) if len(parts) > 4 else ''
                    }

        elif 'handles' in plugin_name:
            if len(parts) >= 7:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process_name': str(parts[1]),
                    'offset': str(parts[2]),
                    'handle_value': str(parts[3]),
                    'type': str(parts[4]),
                    'granted_access': str(parts[5]),
                    'name': str(parts[6]) if len(parts) > 6 else ''
                }

        elif 'envars' in plugin_name and 'linux' not in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process_name': str(parts[1]),
                    'variable': str(parts[2]) if len(parts) > 2 else '',
                    'value': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }

        elif 'svcscan' in plugin_name:
            if len(parts) >= 8:
                header_keywords = ['offset', 'order', 'pid', 'start', 'state', 'type', 'name', 'display', 'binary']
                first_col = str(parts[0]).lower() if parts[0] else ''
                if first_col in header_keywords:
                    return None

                order_str = str(parts[1]) if len(parts) > 1 else ''
                pid_str = str(parts[2]) if len(parts) > 2 else ''

                if not order_str.isdigit() or not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'order': int(order_str),
                    'pid': int(pid_str),
                    'start': str(parts[3]),
                    'state': str(parts[4]),
                    'type': str(parts[5]),
                    'name': str(parts[6]),
                    'display': str(parts[7]),
                    'binary': str(parts[8]) if len(parts) > 8 else '',
                    'binary_registry': str(parts[9]) if len(parts) > 9 else '',
                    'dll': str(parts[10]) if len(parts) > 10 else ''
                }

        elif 'getsids' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process_name': str(parts[1]),
                    'sid': str(parts[2]) if len(parts) > 2 else '',
                    'attributes': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }

        elif 'hashdump' in plugin_name:
            if len(parts) >= 4:
                username = str(parts[0])
                rid_str = str(parts[1]) if len(parts) > 1 else ''
                lm_hash = str(parts[2]) if len(parts) > 2 else ''
                ntlm_hash = str(parts[3]) if len(parts) > 3 else ''

                if not rid_str.isdigit():
                    return None

                def is_valid_hash(h):
                    if not h:
                        return True  
                    return (h == 'aad3b435b51404eeaad3b435b51404ee' or
                            (len(h) == 32 and all(c in '0123456789abcdefABCDEF' for c in h)))

                if username.lower() in ['user', 'username', 'lmhash', 'nthash', 'hash_lm', 'hash_ntlm']:
                    return None

                return {
                    'username': username,
                    'rid': int(rid_str),
                    'hash_lm': lm_hash,
                    'hash_ntlm': ntlm_hash
                }

        elif 'lsadump' in plugin_name:
            if len(parts) >= 2:
                key_name = str(parts[0]) if parts[0] else ''
                value = '\t'.join(parts[1:]) if len(parts) > 1 else ''

                header_keywords = ['key', 'value', 'key name', 'data', 'lsa key']
                if key_name.lower() in header_keywords:
                    return None

                return {
                    'key': key_name,
                    'value': value[:100],  
                    'full_data': value
                }

        elif 'cachedump' in plugin_name:
            if len(parts) >= 4:
                username = str(parts[0]) if parts[0] else ''
                domain = str(parts[1]) if len(parts) > 1 else ''
                domain_name = str(parts[2]) if len(parts) > 2 else ''
                hash_ntlm = str(parts[3]) if len(parts) > 3 else ''

                header_keywords = ['username', 'domain', 'domain_name', 'hash_ntlm', 'hash', 'ntlm']
                if username.lower() in header_keywords:
                    return None

                return {
                    'username': username,
                    'domain': domain,
                    'domain_name': domain_name,
                    'hash_ntlm': hash_ntlm
                }

        elif 'pypykatz' in plugin_name:
            if len(parts) >= 3:
                credtype = str(parts[0]) if parts[0] else ''
                domainname = str(parts[1]) if len(parts) > 1 else ''
                username = str(parts[2]) if len(parts) > 2 else ''
                nt_hash = str(parts[3]) if len(parts) > 3 else ''
                lm_hash = str(parts[4]) if len(parts) > 4 else ''
                sha_hash = str(parts[5]) if len(parts) > 5 else ''
                masterkey = str(parts[6]) if len(parts) > 6 else ''
                masterkey_sha1 = str(parts[7]) if len(parts) > 7 else ''
                key_guid = str(parts[8]) if len(parts) > 8 else ''
                password = str(parts[9]) if len(parts) > 9 else ''

                header_keywords = ['credtype', 'domainname', 'username', 'nthash', 'lmhash', 'shahash',
                                   'masterkey', 'password', 'key_guid']
                if credtype.lower() in header_keywords:
                    return None

                return {
                    'credtype': credtype,
                    'domainname': domainname,
                    'username': username,
                    'nt_hash': nt_hash,
                    'lm_hash': lm_hash,
                    'sha_hash': sha_hash,
                    'masterkey': masterkey,
                    'masterkey_sha1': masterkey_sha1,
                    'key_guid': key_guid,
                    'password': password
                }

        elif 'printkey' in plugin_name:
            if len(parts) >= 6:
                header_keywords = ['last', 'write', 'time', 'hive', 'offset', 'type', 'key', 'name', 'data', 'volatile']
                first_col = str(parts[0]).lower() if parts[0] else ''
                if first_col in header_keywords:
                    return None

                type_value = str(parts[2]) if len(parts) > 2 else ''
                logger.debug(f"printkey 解析: type={type_value}, key={parts[3] if len(parts) > 3 else 'N/A'}, name={parts[4] if len(parts) > 4 else 'N/A'}")
                return {
                    'last_write_time': str(parts[0]) if parts[0] else '',
                    'hive_offset': str(parts[1]) if len(parts) > 1 else '',
                    'type': type_value,
                    'key': str(parts[3]) if len(parts) > 3 else '',
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else '',
                    'volatile': str(parts[6]) if len(parts) > 6 else 'False',
                    '_is_key': type_value == 'Key'  
                }
            else:
                logger.warning(f"printkey 格式不匹配: 期望至少6列，实际{len(parts)}列")
                logger.debug(f"printkey 原始数据 parts: {parts[:10]}")  

                if len(parts) >= 5:
                    type_value = str(parts[2]) if len(parts) > 2 else ''
                    return {
                        'last_write_time': str(parts[0]) if parts[0] else '',
                        'hive_offset': str(parts[1]) if len(parts) > 1 else '',
                        'type': type_value,
                        'key': str(parts[3]) if len(parts) > 3 else '',
                        'name': str(parts[4]) if len(parts) > 4 else '',
                        'data': '',
                        'volatile': 'False',
                        '_is_key': type_value == 'Key'
                    }


        elif 'pslist' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 10:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                file_output = ' '.join(parts[10:]) if len(parts) > 10 else ''
                return {
                    'offset': str(parts[0]),
                    'pid': int(pid_str),
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'uid': int(parts[5]) if len(parts) > 5 and str(parts[5]).isdigit() else 0,
                    'gid': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'euid': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'egid': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'start_time': str(parts[9]) if len(parts) > 9 else '',
                    'file_output': file_output
                }

        elif 'pstree' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 5:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'pid': int(pid_str),
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'bash' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                command = ' '.join(parts[3:]) if len(parts) > 3 else ''
                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'time': str(parts[2]) if len(parts) > 2 else '',
                    'command': command
                }

        elif 'envars' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 5:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'comm': str(parts[2]) if len(parts) > 2 else '',
                    'key': str(parts[3]) if len(parts) > 3 else '',
                    'value': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'elfs' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'file_path': str(parts[4]) if len(parts) > 4 else '',
                    'file_output': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'pagecache' in plugin_name and 'files' in plugin_name.lower():
            if len(parts) >= 13:
                path_value = str(parts[12]) if len(parts) > 12 else ''
                inode_size_val = 0
                if len(parts) > 13:
                    size_str = str(parts[13]).replace(',', '').strip()
                    try:
                        inode_size_val = int(float(size_str))
                    except:
                        inode_size_val = 0

                return {
                    'superblock_addr': str(parts[0]),
                    'mountpoint': str(parts[1]) if len(parts) > 1 else '',
                    'device': str(parts[2]) if len(parts) > 2 else '',
                    'inode_num': int(parts[3]) if len(parts) > 3 and str(parts[3]).replace(',', '').isdigit() else 0,
                    'inode_addr': str(parts[4]) if len(parts) > 4 else '',
                    'file_type': str(parts[5]) if len(parts) > 5 else '',
                    'inode_pages': int(parts[6]) if len(parts) > 6 and str(parts[6]).replace(',', '').isdigit() else 0,
                    'cached_pages': int(parts[7]) if len(parts) > 7 and str(parts[7]).replace(',', '').isdigit() else 0,
                    'file_mode': str(parts[8]) if len(parts) > 8 else '',
                    'access_time': str(parts[9]) if len(parts) > 9 else '',
                    'modification_time': str(parts[10]) if len(parts) > 10 else '',
                    'change_time': str(parts[11]) if len(parts) > 11 else '',
                    'file_path': path_value,  
                    'path': path_value,       
                    'inode_size': inode_size_val,
                    '_can_download': True  
                }
            else:
                logger.debug(f"pagecache.Files 列数不匹配: 期望14列，实际{len(parts)}列")

        elif 'dumpfiles' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 4:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['file', 'path', 'inode', 'size', 'result']
                if first_col in header_keywords:
                    return None

                return {
                    'file_path': str(parts[0]) if parts[0] else '',
                    'inode': str(parts[1]) if len(parts) > 1 else '',
                    'size': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'result': str(parts[3]) if len(parts) > 3 else ''
                }

        elif 'lsof' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 12:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'tid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'process': str(parts[2]) if len(parts) > 2 else '',
                    'fd': int(parts[3]) if len(parts) > 3 and (str(parts[3]).isdigit() or str(parts[3]) == '0') else str(parts[3]),
                    'path': str(parts[4]) if len(parts) > 4 else '',
                    'device': str(parts[5]) if len(parts) > 5 else '',
                    'inode': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'file_type': str(parts[7]) if len(parts) > 7 else '',
                    'mode': str(parts[8]) if len(parts) > 8 else '',
                    'changed': str(parts[9]) if len(parts) > 9 else '',
                    'modified': str(parts[10]) if len(parts) > 10 else '',
                    'accessed': str(parts[11]) if len(parts) > 11 else '',
                    'size': int(parts[12]) if len(parts) > 12 and str(parts[12]).isdigit() else 0
                }
            elif len(parts) >= 4:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'fd': str(parts[1]) if len(parts) > 1 else '',
                    'file_path': str(parts[2]) if len(parts) > 2 else '',
                    'offset': str(parts[3]) if len(parts) > 3 else ''
                }

        elif 'malfind' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 7:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'start': str(parts[1]),
                    'end': str(parts[2]),
                    'protection': str(parts[3]),
                    'permissions': str(parts[4]),
                    'constant': str(parts[5]) if len(parts) > 5 else '',
                    'mapping': str(parts[6]) if len(parts) > 6 else ''
                }

        elif 'capabilities' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'capabilities': str(parts[2]) if len(parts) > 2 else ''
                }

        elif 'check_afinfo' in plugin_name:
            if len(parts) >= 3:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'family': str(parts[1]) if len(parts) > 1 else '',
                    'status': str(parts[2]) if len(parts) > 2 else 'OK'
                }

        elif 'check_creds' in plugin_name:
            if len(parts) >= 4:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'pid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'process': str(parts[2]) if len(parts) > 2 else '',
                    'issue': str(parts[3]) if len(parts) > 3 else ''
                }

        elif 'check_idt' in plugin_name:
            if len(parts) >= 4:
                index_str = str(parts[0]) if parts[0] else ''
                if not index_str.isdigit():
                    return None

                return {
                    'index': int(index_str),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'expected': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        elif 'check_modules' in plugin_name:
            if len(parts) >= 3:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['name', 'offset', 'status', 'ok', 'module']
                if first_col in header_keywords:
                    return None

                return {
                    'name': str(parts[0]),
                    'offset': str(parts[1]) if len(parts) > 1 else '',
                    'status': str(parts[2]) if len(parts) > 2 else 'OK'
                }

        elif 'check_syscall' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                index_str = str(parts[0]) if parts[0] else ''
                if not index_str.isdigit():
                    return None

                return {
                    'index': int(index_str),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'address': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        elif 'iomem' in plugin_name:
            if len(parts) >= 3:
                start = str(parts[0]) if parts[0] else ''
                if not start or not start[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'start': start,
                    'end': str(parts[1]) if len(parts) > 1 else '',
                    'description': str(parts[2]) if len(parts) > 2 else ''
                }

        elif 'keyboard_notifiers' in plugin_name:
            if len(parts) >= 3:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'callback': str(parts[2]) if len(parts) > 2 else ''
                }

        elif 'modxview' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['name', 'address', 'procfs', 'sysfs', 'scan', 'taints']
                if first_col in header_keywords:
                    return None

                return {
                    'name': str(parts[0]),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'in_procfs': str(parts[2]) if len(parts) > 2 else '',
                    'in_sysfs': str(parts[3]) if len(parts) > 3 else '',
                    'in_scan': str(parts[4]) if len(parts) > 4 else '',
                    'taints': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'kmsg' in plugin_name:
            if len(parts) >= 2:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['timestamp', 'time', 'message']
                if first_col in header_keywords:
                    return None

                return {
                    'timestamp': str(parts[0]),
                    'message': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        elif 'lsmod' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 5:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                code_size = 0
                size_str = str(parts[2]).strip()
                if size_str.startswith('0x') or size_str.startswith('0X'):
                    try:
                        code_size = int(size_str, 16)
                    except ValueError:
                        code_size = 0
                elif size_str.isdigit():
                    code_size = int(size_str)

                load_args = ''
                file_output = ''
                if len(parts) > 5:
                    if len(parts) >= 6:
                        file_output = str(parts[-1]).strip()
                        load_args = ' '.join(parts[4:-1]).strip()
                    else:
                        load_args = str(parts[4]).strip()

                return {
                    'offset': offset,
                    'name': str(parts[1]).strip() if len(parts) > 1 else '',
                    'code_size': code_size,
                    'taints': str(parts[3]).strip() if len(parts) > 3 else '',
                    'load_arguments': load_args,
                    'file_output': file_output
                }

        elif 'mountinfo' in plugin_name:
            if len(parts) >= 5:
                mount_id_str = str(parts[0]) if parts[0] else ''
                if not mount_id_str.isdigit():
                    return None

                result = {
                    'mount_id': int(mount_id_str),
                    'parent_id': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'device': str(parts[2]).strip() if len(parts) > 2 else '',  
                    'major_minor': str(parts[2]).strip() if len(parts) > 2 else '',
                    'root': str(parts[3]).strip() if len(parts) > 3 else '',
                    'mount_point': str(parts[4]).strip() if len(parts) > 4 else '',
                    'options': str(parts[5]).strip() if len(parts) > 5 else '',
                }

                if len(parts) > 6:
                    val = str(parts[6]).strip()
                    if val and val != '-':
                        result['optional_fields'] = val
                if len(parts) > 7:
                    val = str(parts[7]).strip()
                    if val and val != '-':
                        result['separator'] = val
                if len(parts) > 8:
                    val = str(parts[8]).strip()
                    if val and val != '-':
                        result['filesystem_type'] = val
                if len(parts) > 9:
                    val = str(parts[9]).strip()
                    if val and val != '-':
                        result['mount_source'] = val
                if len(parts) > 10:
                    val = str(parts[10]).strip()
                    if val and val != '-':
                        result['super_options'] = val

                return result

        elif ('maps' in plugin_name or 'proc.Maps' in plugin_name) and 'linux' in plugin_name.lower():
            if len(parts) >= 11:
                path_value = str(parts[9]) if len(parts) > 9 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'permissions': str(parts[4]) if len(parts) > 4 else '',
                    'offset': str(parts[5]) if len(parts) > 5 else '',
                    'major': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'minor': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'inode': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'path': path_value,
                    'name': path_value,  
                    'file_output': str(parts[10]) if len(parts) > 10 else ''
                }
            elif len(parts) >= 10:
                path_value = str(parts[9]) if len(parts) > 9 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'permissions': str(parts[4]) if len(parts) > 4 else '',
                    'offset': str(parts[5]) if len(parts) > 5 else '',
                    'major': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'minor': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'inode': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'path': path_value,
                    'name': path_value,  
                    'file_output': ''
                }

        elif 'psaux' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                args = ' '.join(parts[3:]) if len(parts) > 3 else ''
                return {
                    'pid': int(pid_str),
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'comm': str(parts[2]) if len(parts) > 2 else '',
                    'args': args
                }

        elif 'psscan' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'pid': int(pid_str),
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'exit_state': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'sockstat' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 15:
                netns_str = str(parts[0]) if parts[0] else ''
                if not netns_str.isdigit():
                    return None

                return {
                    'netns': int(netns_str),
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'tid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'fd': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'sock_offset': str(parts[5]) if len(parts) > 5 else '',
                    'family': str(parts[6]) if len(parts) > 6 else '',
                    'type': str(parts[7]) if len(parts) > 7 else '',
                    'proto': str(parts[8]) if len(parts) > 8 else '',
                    'source_addr': str(parts[9]) if len(parts) > 9 else '',
                    'source_port': str(parts[10]) if len(parts) > 10 else '',
                    'dest_addr': str(parts[11]) if len(parts) > 11 else '',
                    'dest_port': str(parts[12]) if len(parts) > 12 else '',
                    'state': str(parts[13]) if len(parts) > 13 else '',
                    'filter': str(parts[14]) if len(parts) > 14 else ''
                }

        elif 'tty_check' in plugin_name:
            if len(parts) >= 4:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'tty': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        elif 'vmayarascan' in plugin_name:
            if len(parts) >= 5:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'offset': str(parts[2]) if len(parts) > 2 else '',
                    'rule': str(parts[3]) if len(parts) > 3 else '',
                    'matches': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0
                }

        elif 'netstat' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 10 and str(parts[0]).lower().startswith('0x'):
                pid_str = str(parts[7]) if len(parts) > 7 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'protocol': str(parts[1]),
                    'local_address': str(parts[2]),
                    'local_port': str(parts[3]),
                    'remote_address': str(parts[4]),
                    'foreign_address': str(parts[4]),
                    'remote_port': str(parts[5]),
                    'foreign_port': str(parts[5]),
                    'state': str(parts[6]),
                    'pid': int(pid_str),
                    'process_name': str(parts[8]) if len(parts) > 8 else '',
                    'create_time': str(parts[9]) if len(parts) > 9 else ''
                }

            if len(parts) >= 8:
                pid_str = str(parts[6]) if len(parts) > 6 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'foreign_address': str(parts[3]),
                    'remote_address': str(parts[3]),
                    'foreign_port': str(parts[4]),
                    'remote_port': str(parts[4]),
                    'state': str(parts[5]),
                    'pid': int(pid_str),
                    'process_name': str(parts[7]) if len(parts) > 7 else ''
                }

        elif 'netfilter' in plugin_name:
            if len(parts) >= 6:
                protocol = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['proto', 'protocol', 'srcaddr', 'dstaddr', 'state', 'source', 'destination']
                if protocol in header_keywords:
                    return None

                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'remote_address': str(parts[3]),
                    'remote_port': str(parts[4]),
                    'state': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'netstat' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 15:
                netns_str = str(parts[0]) if parts[0] else ''
                if not netns_str.isdigit():
                    return None

                return {
                    'netns': int(netns_str),
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'tid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'fd': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'sock_offset': str(parts[5]) if len(parts) > 5 else '',
                    'family': str(parts[6]) if len(parts) > 6 else '',
                    'type': str(parts[7]) if len(parts) > 7 else '',
                    'proto': str(parts[8]) if len(parts) > 8 else '',
                    'source_addr': str(parts[9]) if len(parts) > 9 else '',
                    'source_port': str(parts[10]) if len(parts) > 10 else '',
                    'dest_addr': str(parts[11]) if len(parts) > 11 else '',
                    'dest_port': str(parts[12]) if len(parts) > 12 else '',
                    'state': str(parts[13]) if len(parts) > 13 else '',
                    'filter': str(parts[14]) if len(parts) > 14 else ''
                }
            elif len(parts) >= 6:
                protocol = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['proto', 'protocol', 'srcaddr', 'dstaddr', 'state', 'source', 'destination']
                if protocol in header_keywords:
                    return None

                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'remote_address': str(parts[3]),
                    'remote_port': str(parts[4]),
                    'state': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'ip.addr' in plugin_name.lower() or 'linux_ip_addr' in plugin_name.lower():
            if len(parts) >= 8:
                netns = int(parts[0]) if str(parts[0]).strip().isdigit() else 0
                index = int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0
                interface = str(parts[2]).strip() if len(parts) > 2 else ''
                mac = str(parts[3]).strip() if len(parts) > 3 else ''
                promiscuous = str(parts[4]).strip() if len(parts) > 4 else ''
                ip = str(parts[5]).strip() if len(parts) > 5 else ''
                prefix = int(parts[6]) if len(parts) > 6 and str(parts[6]).strip().isdigit() else 0

                scope_type = str(parts[7]).strip() if len(parts) > 7 else ''

                type_value = str(parts[8]).strip() if len(parts) > 8 else '-'
                if not type_value:
                    type_value = '-'

                state = str(parts[9]).strip() if len(parts) > 9 else ''

                return {
                    'netns': netns,
                    'index': index,
                    'interface': interface,
                    'mac': mac,
                    'promiscuous': promiscuous,
                    'ip': ip,
                    'prefix': prefix,
                    'scope_type': scope_type,
                    'type': type_value,
                    'state': state
                }

        elif 'ip.link' in plugin_name.lower() or 'linux_ip_link' in plugin_name.lower():
            if len(parts) >= 8:
                return {
                    'netns': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'index': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'interface': str(parts[2]) if len(parts) > 2 else '',
                    'mac': str(parts[3]) if len(parts) > 3 else '',
                    'promiscuous': str(parts[4]) if len(parts) > 4 else '',
                    'state': str(parts[5]) if len(parts) > 5 else '',
                    'mtu': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'qdisc': str(parts[7]) if len(parts) > 7 else ''
                }


        elif 'pslist' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'name': str(parts[1]),
                    'pid': int(parts[2]) if str(parts[2]).strip().isdigit() else 0,
                    'uid': int(parts[3]) if len(parts) > 3 and str(parts[3]).strip().isdigit() else 0,
                    'gid': int(parts[4]) if len(parts) > 4 and str(parts[4]).strip().isdigit() else 0,
                    'start_time': str(parts[5]) if len(parts) > 5 else '',
                    'ppid': int(parts[6]) if len(parts) > 6 and str(parts[6]).strip().isdigit() else 0
                }

        elif 'pstree' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'name': str(parts[2]) if len(parts) > 2 else ''
                }

        elif 'envars' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'variable': str(parts[1]) if len(parts) > 1 else '',
                    'value': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        elif 'netstat' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'protocol': str(parts[1]) if len(parts) > 1 else '',
                    'local_address': str(parts[2]) if len(parts) > 2 else '',
                    'local_port': str(parts[3]) if len(parts) > 3 else '',
                    'remote_address': str(parts[4]) if len(parts) > 4 else '',
                    'remote_port': str(parts[5]) if len(parts) > 5 else '',
                    'state': str(parts[6]) if len(parts) > 6 else '',
                    'process': ' '.join(parts[7:]) if len(parts) > 7 else ''
                }

        elif 'dmesg' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 1:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['line', 'message', 'timestamp']
                if first_col in header_keywords:
                    return None

                return {
                    'line': ' '.join(parts)
                }

        elif 'ifconfig' in plugin_name:
            if len(parts) >= 4:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['interface', 'ip', 'mac', 'address', 'promiscuous', 'status']
                if first_col in header_keywords:
                    return None

                interface = str(parts[0])
                potential_ip_or_mac = str(parts[1]) if len(parts) > 1 else ''
                potential_mac = str(parts[2]) if len(parts) > 2 else ''
                promiscuous_value = str(parts[3]) if len(parts) > 3 else ''

                if ':' in potential_ip_or_mac and potential_ip_or_mac.count(':') >= 5:
                    mac_address = potential_ip_or_mac
                    ip_address = ''
                else:
                    ip_address = potential_ip_or_mac
                    mac_address = potential_mac

                return {
                    'interface': interface,
                    'ip_address': ip_address,
                    'mac_address': mac_address,
                    'promiscuous': promiscuous_value,
                    'status': promiscuous_value  
                }

        elif 'kauth_listeners' in plugin_name:
            if len(parts) >= 4:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['name', 'idata', 'callback', 'address', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'name': str(parts[0]),
                    'idata': str(parts[1]) if len(parts) > 1 else '',
                    'callback_address': str(parts[2]) if len(parts) > 2 else '',
                    'module': str(parts[3]) if len(parts) > 3 else '',
                    'symbol': ' '.join(parts[4:]) if len(parts) > 4 else ''
                }

        elif 'kauth_scopes' in plugin_name:
            if len(parts) >= 5:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['name', 'idata', 'listeners', 'callback', 'address', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'name': str(parts[0]),
                    'idata': str(parts[1]) if len(parts) > 1 else '',
                    'listeners': str(parts[2]) if len(parts) > 2 else '',
                    'callback_address': str(parts[3]) if len(parts) > 3 else '',
                    'module': str(parts[4]) if len(parts) > 4 else '',
                    'symbol': ' '.join(parts[5:]) if len(parts) > 5 else ''
                }

        elif 'kevents' in plugin_name:
            if len(parts) >= 4:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'ident': str(parts[2]) if len(parts) > 2 else '',
                    'filter': str(parts[3]) if len(parts) > 3 else '',
                    'context': ' '.join(parts[4:]) if len(parts) > 4 else ''
                }

        elif 'list_files' in plugin_name:
            if len(parts) >= 2:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'path': str(parts[1]) if len(parts) > 1 else '',
                    'name': str(parts[1]) if len(parts) > 1 else ''  
                }

        elif 'lsmod' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'size': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0
                }

        elif 'lsof' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                fd_value = str(parts[1]) if len(parts) > 1 else ''
                return {
                    'pid': int(pid_str),
                    'file_descriptor': fd_value,
                    'fd': fd_value,  
                    'file_path': str(parts[2]) if len(parts) > 2 else ''
                }

        elif 'mount' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['device', 'mount', 'point', 'type', 'on']
                if first_col in header_keywords:
                    return None

                return {
                    'device': str(parts[0]),
                    'mount_point': str(parts[1]) if len(parts) > 1 else '',
                    'type': str(parts[2]) if len(parts) > 2 else ''
                }

        elif ('maps' in plugin_name or 'proc.Maps' in plugin_name or 'proc_maps' in plugin_name) and 'mac' in plugin_name.lower():
            if len(parts) >= 7:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                protection_value = str(parts[4]) if len(parts) > 4 else ''
                map_name_value = str(parts[5]) if len(parts) > 5 else ''
                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': protection_value,
                    'permissions': protection_value,  
                    'map_name': map_name_value,
                    'name': map_name_value,  
                    'file_output': str(parts[6]) if len(parts) > 6 else ''
                }
            elif len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                protection_value = str(parts[4]) if len(parts) > 4 else ''
                map_name_value = str(parts[5]) if len(parts) > 5 else ''
                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': protection_value,
                    'permissions': protection_value,  
                    'map_name': map_name_value,
                    'name': map_name_value,  
                    'file_output': ''
                }

        elif 'psaux' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                process = str(parts[1]) if len(parts) > 1 else ''
                arguments = ' '.join(parts[3:]) if len(parts) > 3 else ''
                command = f"{process} {arguments}".strip()
                return {
                    'pid': int(pid_str),
                    'process': process,
                    'argc': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'arguments': arguments,
                    'user': '',
                    'cpu': '',
                    'mem': '',
                    'vsz': '',
                    'rss': '',
                    'tty': '',
                    'command': command
                }

        elif 'socket_filters' in plugin_name:
            if len(parts) >= 7:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['filter', 'name', 'member', 'socket', 'handler', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'filter': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'member': str(parts[2]) if len(parts) > 2 else '',
                    'socket': str(parts[3]) if len(parts) > 3 else '',
                    'handler': str(parts[4]) if len(parts) > 4 else '',
                    'module': str(parts[5]) if len(parts) > 5 else '',
                    'symbol': str(parts[6]) if len(parts) > 6 else ''
                }
            elif len(parts) >= 4:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['filter', 'name', 'member', 'socket']
                if first_col in header_keywords:
                    return None

                return {
                    'filter': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'member': str(parts[2]) if len(parts) > 2 else '',
                    'socket': str(parts[3]) if len(parts) > 3 else '',
                    'handler': '',
                    'module': '',
                    'symbol': ''
                }

        elif 'timers' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['function', 'param', 'deadline', 'entry', 'time', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'function': str(parts[0]),
                    'param_0': str(parts[1]) if len(parts) > 1 else '',
                    'param_1': str(parts[2]) if len(parts) > 2 else '',
                    'deadline': str(parts[3]) if len(parts) > 3 else '',
                    'entry_time': str(parts[4]) if len(parts) > 4 else '',
                    'module': str(parts[5]) if len(parts) > 5 else '',
                    'symbol': ' '.join(parts[6:]) if len(parts) > 6 else ''
                }

        elif 'trustedbsd' in plugin_name:
            if len(parts) >= 5:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['member', 'policy', 'name', 'handler', 'address', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'member': str(parts[0]),
                    'policy_name': str(parts[1]) if len(parts) > 1 else '',
                    'handler_address': str(parts[2]) if len(parts) > 2 else '',
                    'handler_module': str(parts[3]) if len(parts) > 3 else '',
                    'handler_symbol': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'vfsevents' in plugin_name:
            if len(parts) >= 3:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'name': str(parts[0]),
                    'pid': int(pid_str),
                    'events': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        elif 'check_syscall' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['table', 'address', 'name', 'index', 'handler', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'table_address': str(parts[0]),
                    'table_name': str(parts[1]) if len(parts) > 1 else '',
                    'index': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'handler_module': str(parts[4]) if len(parts) > 4 else '',
                    'handler_symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'check_sysctl' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['name', 'number', 'perms', 'handler', 'address', 'value', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'name': str(parts[0]),
                    'number': str(parts[1]) if len(parts) > 1 else '',
                    'perms': str(parts[2]) if len(parts) > 2 else '',
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'value': str(parts[4]) if len(parts) > 4 else '',
                    'handler_module': str(parts[5]) if len(parts) > 5 else '',
                    'handler_symbol': str(parts[6]) if len(parts) > 6 else ''
                }

        elif 'check_trap_table' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['table', 'address', 'name', 'index', 'handler', 'module', 'symbol']
                if first_col in header_keywords:
                    return None

                return {
                    'table_address': str(parts[0]),
                    'table_name': str(parts[1]) if len(parts) > 1 else '',
                    'index': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'handler_module': str(parts[4]) if len(parts) > 4 else '',
                    'handler_symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'malfind' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': str(parts[4]) if len(parts) > 4 else '',
                    'hexdump': str(parts[5]) if len(parts) > 5 else '',
                    'disasm': ' '.join(parts[6:]) if len(parts) > 6 else ''
                }

        elif 'bash' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 4:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'command_time': str(parts[2]) if len(parts) > 2 else '',
                    'command': str(parts[3]) if len(parts) > 3 else ''
                }

        elif 'cmdscan' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'console_info': str(parts[2]) if len(parts) > 2 else '',
                    'property': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'consoles' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'console_info': str(parts[2]) if len(parts) > 2 else '',
                    'property': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'psxview' in plugin_name:
            if len(parts) >= 8:
                pid_str = str(parts[2]) if len(parts) > 2 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(pid_str) if pid_str.isdigit() else 0,
                    'pslist': str(parts[3]) if len(parts) > 3 else '',
                    'psscan': str(parts[4]) if len(parts) > 4 else '',
                    'thrdscan': str(parts[5]) if len(parts) > 5 else '',
                    'csrss': str(parts[6]) if len(parts) > 6 else '',
                    'exit_time': str(parts[7]) if len(parts) > 7 else ''
                }

        elif 'callbacks' in plugin_name:
            if len(parts) >= 5:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['type', 'callback', 'module', 'symbol', 'detail']
                if first_col in header_keywords:
                    return None

                return {
                    'type': str(parts[0]),
                    'callback': str(parts[1]) if len(parts) > 1 else '',
                    'module': str(parts[2]) if len(parts) > 2 else '',
                    'symbol': str(parts[3]) if len(parts) > 3 else '',
                    'detail': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'privileges' in plugin_name or 'privs' in plugin_name:
            if len(parts) >= 6:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'value': str(parts[2]) if len(parts) > 2 else '',
                    'privilege': str(parts[3]) if len(parts) > 3 else '',
                    'attributes': str(parts[4]) if len(parts) > 4 else '',
                    'description': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'sessions' in plugin_name:
            if len(parts) >= 6:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['sessionid', 'session', 'type', 'pid', 'process', 'user', 'name', 'create']
                if first_col in header_keywords:
                    return None

                return {
                    'session_id': str(parts[0]),
                    'session_type': str(parts[1]),
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'process': str(parts[3]) if len(parts) > 3 else '',
                    'user_name': str(parts[4]) if len(parts) > 4 else '',
                    'create_time': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'suspicious_threads' in plugin_name:
            if len(parts) >= 7:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                vad_path_parts = []
                note_parts = []
                in_vad_path = True

                for i in range(5, len(parts)):
                    part = parts[i]
                    if in_vad_path and part in ['This', 'Thread', 'A', 'The', 'Possible']:
                        in_vad_path = False
                        note_parts.append(part)
                    elif in_vad_path:
                        vad_path_parts.append(part)
                    else:
                        note_parts.append(part)

                vad_path = ' '.join(vad_path_parts) if vad_path_parts else (str(parts[5]) if len(parts) > 5 else '')
                note = ' '.join(note_parts) if note_parts else (str(parts[6]) if len(parts) > 6 else '')

                return {
                    'process': str(parts[0]),
                    'pid': int(pid_str),
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'context': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'vad_path': vad_path,
                    'note': note
                }

        elif 'threads' in plugin_name:
            if len(parts) >= 9:
                pid_str = str(parts[1]) if len(parts) > 1 else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'offset': str(parts[0]),
                    'pid': int(pid_str),
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'start_address': str(parts[3]) if len(parts) > 3 else '',
                    'start_path': str(parts[4]) if len(parts) > 4 else '',
                    'win32_start_address': str(parts[5]) if len(parts) > 5 else '',
                    'win32_start_path': str(parts[6]) if len(parts) > 6 else '',
                    'create_time': str(parts[7]) if len(parts) > 7 else '',
                    'exit_time': str(parts[8]) if len(parts) > 8 else ''
                }

        elif 'vadinfo' in plugin_name:
            if len(parts) >= 12:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                result = {
                    'pid': int(pid_str),
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'offset': str(parts[2]) if len(parts) > 2 else '',
                    'start_vpn': str(parts[3]) if len(parts) > 3 else '',
                    'end_vpn': str(parts[4]) if len(parts) > 4 else '',
                    'tag': str(parts[5]) if len(parts) > 5 else '',
                    'protection': str(parts[6]) if len(parts) > 6 else '',
                    'commit_charge': int(parts[7]) if len(parts) > 7 and str(parts[7]).strip().isdigit() else 0,
                    'private_memory': int(parts[8]) if len(parts) > 8 and str(parts[8]).strip().isdigit() else 0,
                    'parent': str(parts[9]) if len(parts) > 9 else '',
                    'file': str(parts[10]) if len(parts) > 10 else '',
                    'file_output': str(parts[11]) if len(parts) > 11 else ''
                }
                logger.debug(f"vadinfo 解析: file={result['file']}, parts[10]={parts[10] if len(parts) > 10 else 'N/A'}")
                return result

        elif 'mutantscan' in plugin_name:
            if len(parts) >= 2:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'name': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        elif 'modscan' in plugin_name:
            if len(parts) >= 6:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'base': str(parts[1]) if len(parts) > 1 else '',
                    'size': str(parts[2]) if len(parts) > 2 else '',
                    'name': str(parts[3]) if len(parts) > 3 else '',
                    'path': str(parts[4]) if len(parts) > 4 else '',
                    'file_output': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'ssdt' in plugin_name:
            if len(parts) >= 4:
                index_str = str(parts[0]) if parts[0] else ''
                if not index_str.isdigit():
                    return None

                return {
                    'index': int(index_str),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'service': str(parts[2]) if len(parts) > 2 else '',
                    'symbol': str(parts[3]) if len(parts) > 3 else ''
                }

        elif 'driverscan' in plugin_name:
            if len(parts) >= 6:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'start': str(parts[1]) if len(parts) > 1 else '',
                    'size': str(parts[2]) if len(parts) > 2 else '',
                    'service_key': str(parts[3]) if len(parts) > 3 else '',
                    'driver_name': str(parts[4]) if len(parts) > 4 else '',
                    'name': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'drivermodule' in plugin_name:
            if len(parts) >= 5:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'known_exception': str(parts[1]) if len(parts) > 1 else '',
                    'driver_name': str(parts[2]) if len(parts) > 2 else '',
                    'service_key': str(parts[3]) if len(parts) > 3 else '',
                    'alternative_name': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'driverirp' in plugin_name:
            if len(parts) >= 6:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'driver_name': str(parts[1]) if len(parts) > 1 else '',
                    'irp': str(parts[2]) if len(parts) > 2 else '',
                    'address': str(parts[3]) if len(parts) > 3 else '',
                    'module': str(parts[4]) if len(parts) > 4 else '',
                    'symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'shimcachemem' in plugin_name:
            if len(parts) >= 6:
                order_str = str(parts[0]) if parts[0] else ''
                if not order_str.isdigit():
                    return None

                return {
                    'order': int(order_str),
                    'last_modified': str(parts[1]) if len(parts) > 1 else '',
                    'last_update': str(parts[2]) if len(parts) > 2 else '',
                    'exec_flag': str(parts[3]) if len(parts) > 3 else '',
                    'file_size': str(parts[4]) if len(parts) > 4 else '',
                    'file_path': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'mftscan' in plugin_name:
            if len(parts) >= 12:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'record_type': str(parts[1]) if len(parts) > 1 else '',
                    'record_number': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'link_count': int(parts[3]) if len(parts) > 3 and str(parts[3]).strip().isdigit() else 0,
                    'mft_type': str(parts[4]) if len(parts) > 4 else '',
                    'permissions': str(parts[5]) if len(parts) > 5 else '',
                    'attribute_type': str(parts[6]) if len(parts) > 6 else '',
                    'created': str(parts[7]) if len(parts) > 7 else '',
                    'modified': str(parts[8]) if len(parts) > 8 else '',
                    'updated': str(parts[9]) if len(parts) > 9 else '',
                    'accessed': str(parts[10]) if len(parts) > 10 else '',
                    'filename': str(parts[11]) if len(parts) > 11 else ''
                }

        elif 'mbrscan' in plugin_name:
            if len(parts) >= 9:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'disk_signature': str(parts[1]) if len(parts) > 1 else '',
                    'bootcode_md5': str(parts[2]) if len(parts) > 2 else '',
                    'full_mbr_md5': str(parts[3]) if len(parts) > 3 else '',
                    'partition_index': int(parts[4]) if len(parts) > 4 and str(parts[4]).strip().isdigit() else 0,
                    'bootable': str(parts[5]) if len(parts) > 5 else '',
                    'partition_type': str(parts[6]) if len(parts) > 6 else '',
                    'sector_size': str(parts[7]) if len(parts) > 7 else '',
                    'disasm': str(parts[8]) if len(parts) > 8 else ''
                }

        elif 'crashinfo' in plugin_name:
            if len(parts) >= 7:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['signature', 'major', 'minor', 'version', 'directory', 'table', 'base']
                if first_col in header_keywords:
                    return None

                return {
                    'signature': str(parts[0]),
                    'major_version': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'minor_version': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'directory_table_base': str(parts[3]) if len(parts) > 3 else '',
                    'pfn_data_base': str(parts[4]) if len(parts) > 4 else '',
                    'ps_loaded_module_list': str(parts[5]) if len(parts) > 5 else '',
                    'ps_active_process_head': str(parts[6]) if len(parts) > 6 else ''
                }

        elif 'deskscan' in plugin_name or 'desktops' in plugin_name:
            if len(parts) >= 6:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'window_station': str(parts[1]) if len(parts) > 1 else '',
                    'session': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'desktop': str(parts[3]) if len(parts) > 3 else '',
                    'process': str(parts[4]) if len(parts) > 4 else '',
                    'pid': int(parts[5]) if len(parts) > 5 and str(parts[5]).strip().isdigit() else 0
                }

        elif 'devicetree' in plugin_name:
            if len(parts) >= 6:
                offset = str(parts[0]) if parts[0] else ''
                if not offset or not offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'offset': offset,
                    'type': str(parts[1]) if len(parts) > 1 else '',
                    'driver_name': str(parts[2]) if len(parts) > 2 else '',
                    'device_name': str(parts[3]) if len(parts) > 3 else '',
                    'driver_name_of_att_device': str(parts[4]) if len(parts) > 4 else '',
                    'device_type': str(parts[5]) if len(parts) > 5 else ''
                }

        elif 'bigpools' in plugin_name:
            if len(parts) >= 5:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['allocation', 'tag', 'pooltype', 'pool', 'type', 'number', 'bytes', 'status']
                if first_col in header_keywords:
                    return None

                return {
                    'allocation': str(parts[0]),
                    'tag': str(parts[1]) if len(parts) > 1 else '',
                    'pool_type': str(parts[2]) if len(parts) > 2 else '',
                    'number_of_bytes': str(parts[3]) if len(parts) > 3 else '',
                    'status': str(parts[4]) if len(parts) > 4 else ''
                }

        elif 'skeleton_key_check' in plugin_name:
            if len(parts) >= 1:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['status', 'message', 'skeleton', 'key', 'lsa']
                if first_col in header_keywords:
                    return None

                return {
                    'status': str(parts[0]),
                    'message': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        elif 'truecrypt' in plugin_name:
            if len(parts) >= 2:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['type', 'password', 'truecrypt', 'passphrase']
                if first_col in header_keywords:
                    return None

                return {
                    'type': str(parts[0]),
                    'password': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        elif 'userassist' in plugin_name:
            clean = [p for p in parts if p.strip()]
            if not clean:
                return None
            first = clean[0].strip()
            if first == '*':
                clean.pop(0)
            elif first.startswith('* '):
                clean[0] = first[2:].strip()  
            else:
                return None  

            if len(clean) >= 7:
                hive_offset = str(clean[0]).strip()
                if not hive_offset or not hive_offset[0].lower() in '0123456789abcdef':
                    return None

                return {
                    'hive_offset': hive_offset,
                    'hive_name': str(clean[1]),
                    'path': str(clean[2]),
                    'last_write_time': str(clean[3]),
                    'type': str(clean[4]),
                    'name': str(clean[5]),
                    'id': str(clean[6]),
                    'count': int(clean[7]) if len(clean) > 7 and str(clean[7]).strip().isdigit() else 0,
                    'focus_count': int(clean[8]) if len(clean) > 8 and str(clean[8]).strip().isdigit() else 0,
                    'time_focused': str(clean[9]) if len(clean) > 9 else '',
                    'last_updated': str(clean[10]) if len(clean) > 10 else '',
                    'raw_data': ''
                }

        elif 'scheduled_tasks' in plugin_name:
            if len(parts) >= 2:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['taskname', 'task', 'name', 'principal', 'display', 'enabled', 'creation', 'scheduled']
                if first_col in header_keywords:
                    return None

                return {
                    'task_name': str(parts[0]),
                    'principal_id': str(parts[1]) if len(parts) > 1 else '',
                    'display_name': str(parts[2]) if len(parts) > 2 else '',
                    'enabled': str(parts[3]) if len(parts) > 3 else '',
                    'creation_time': str(parts[4]) if len(parts) > 4 else '',
                    'last_run_time': str(parts[5]) if len(parts) > 5 else '',
                    'last_successful_run_time': str(parts[6]) if len(parts) > 6 else '',
                    'trigger_type': str(parts[7]) if len(parts) > 7 else '',
                    'trigger_description': str(parts[8]) if len(parts) > 8 else '',
                    'action_type': str(parts[9]) if len(parts) > 9 else '',
                    'action': str(parts[10]) if len(parts) > 10 else '',
                    'action_arguments': str(parts[11]) if len(parts) > 11 else '',
                    'action_context': str(parts[12]) if len(parts) > 12 else '',
                    'working_directory': str(parts[13]) if len(parts) > 13 else '',
                    'key_name': str(parts[14]) if len(parts) > 14 else ''
                }

        elif 'amcache' in plugin_name:
            if len(parts) >= 11:
                first_col = str(parts[0]).lower() if parts[0] else ''
                header_keywords = ['entrytype', 'entry', 'type', 'path', 'company', 'amcache', 'program']
                if first_col in header_keywords:
                    return None

                return {
                    'entry_type': str(parts[0]),
                    'path': str(parts[1]) if len(parts) > 1 else '',
                    'company': str(parts[2]) if len(parts) > 2 else '',
                    'last_modify_time': str(parts[3]) if len(parts) > 3 else '',
                    'last_modify_time2': str(parts[4]) if len(parts) > 4 else '',
                    'install_time': str(parts[5]) if len(parts) > 5 else '',
                    'compile_time': str(parts[6]) if len(parts) > 6 else '',
                    'sha1': str(parts[7]) if len(parts) > 7 else '',
                    'service': str(parts[8]) if len(parts) > 8 else '',
                    'product_name': str(parts[9]) if len(parts) > 9 else '',
                    'product_version': str(parts[10]) if len(parts) > 10 else ''
                }

        elif 'ldrmodules' in plugin_name:
            if len(parts) >= 7:
                pid_str = str(parts[0]) if parts[0] else ''
                if not pid_str.isdigit():
                    return None

                return {
                    'pid': int(pid_str) if pid_str.isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'base': str(parts[2]) if len(parts) > 2 else '',
                    'inload': str(parts[3]) if len(parts) > 3 else '',
                    'ininit': str(parts[4]) if len(parts) > 4 else '',
                    'inmem': str(parts[5]) if len(parts) > 5 else '',
                    'mappedpath': str(parts[6]) if len(parts) > 6 else ''
                }

        elif 'windows.info' in plugin_name:
            if len(parts) >= 2:
                variable = str(parts[0]).strip()
                value = '\t'.join(parts[1:]).strip()
                _info_labels = {
                    'Kernel Base': '内核基址',
                    'DTB': '目录表基址',
                    'Symbols': '符号表',
                    'Is64Bit': '64位系统',
                    'IsPAE': 'PAE寻址',
                    'KdDebuggerDataBlock': '内核调试数据块',
                    'NTBuildLab': '系统构建版本',
                    'CSDVersion': 'Service Pack',
                    'KdVersionBlock': '内核版本块',
                    'Major/Minor': '主/次版本',
                    'MachineType': '机器类型',
                    'KeNumberProcessors': '处理器数量',
                    'SystemTime': '系统时间',
                    'NtSystemRoot': '系统目录',
                    'NtProductType': '产品类型',
                    'NtMajorVersion': '主版本号',
                    'NtMinorVersion': '次版本号',
                    'PE MajorOperatingSystemVersion': 'PE 操作系统主版本',
                    'PE MinorOperatingSystemVersion': 'PE 操作系统次版本',
                    'PE Machine': 'PE 机器类型',
                    'PE TimeDateStamp': 'PE 编译时间',
                }
                return {
                    'variable': variable,
                    'label': _info_labels.get(variable, ''),
                    'value': value
                }

        return None

    @staticmethod
    def check_all_dependencies(python_path: str = None) -> Dict[str, Any]:
        import subprocess
        import platform

        dependencies = {
            'volatility3': {'installed': False, 'version': None, 'error': None},
            'pycryptodome': {'installed': False, 'version': None, 'error': None},
            'pypykatz': {'installed': False, 'version': None, 'error': None},
            'openai': {'installed': False, 'version': None, 'error': None, 'optional': True, 'category': 'ai'},
        }
        probe_errors = {}

        if python_path:
            python_cmd = python_path
            import shutil as _shutil
            if not ('/' in python_cmd or '\\' in python_cmd or python_cmd.startswith('.')):
                resolved = _shutil.which(python_cmd)
                if resolved:
                    python_cmd = resolved
            logger.info(f"使用 Python 路径检测依赖: {python_cmd}")
        else:
            is_frozen = getattr(sys, 'frozen', False)
            is_nuitka = hasattr(sys, 'nuitka_version') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
            )
            is_macos_app = '.app/Contents/MacOS' in (sys.executable or '') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and '.app/Contents/MacOS' in sys.argv[0]
            )
            is_packaged = is_frozen or is_nuitka or is_macos_app

            system = platform.system()
            if is_packaged:
                if system == 'Windows':
                    python_cmd = 'python'
                else:
                    python_cmd = 'python3'
                import shutil as _shutil2
                resolved = _shutil2.which(python_cmd)
                if resolved:
                    python_cmd = resolved
                logger.info(f"打包环境检测依赖，使用系统 Python: {python_cmd}")
            else:
                python_cmd = sys.executable

        def check_dependency(package_name: str, import_statement: str, version_statement: str = None) -> tuple:
            import os as _os
            subprocess_kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
            if platform.system() == 'Windows':
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            elif platform.system() == 'Darwin':
                subprocess_kwargs.setdefault('encoding', 'utf-8')
                subprocess_kwargs.setdefault('errors', 'replace')
            clean_env = _get_clean_python_env()
            subprocess_kwargs['env'] = clean_env
            subprocess_kwargs['cwd'] = _get_safe_subprocess_cwd()

            try:
                result = subprocess.run(
                    [python_cmd, '-c', import_statement],
                    **subprocess_kwargs
                )
                if result.returncode != 0:
                    stderr = (result.stderr or '').strip()
                    logger.info(f"依赖 {package_name} 不可导入: {stderr}")
                    if stderr and not any(marker in stderr for marker in (
                        'ModuleNotFoundError', 'ImportError', 'No module named'
                    )):
                        detail = stderr.splitlines()[-1]
                        probe_errors[package_name] = f'检测环境异常: {detail}'
                    return False, None

                version = None
                if version_statement:
                    try:
                        ver_result = subprocess.run(
                            [python_cmd, '-c', version_statement],
                            **subprocess_kwargs
                        )
                        if ver_result.returncode == 0:
                            version = ver_result.stdout.strip()
                    except Exception:
                        pass

                return True, version
            except Exception as e:
                logger.warning(f"检查依赖 {package_name} 时出错: {e}")
                probe_errors[package_name] = f'检测环境异常: {e}'
                return False, None

        installed, version = check_dependency(
            'volatility3',
            'import volatility3',
            'import pkg_resources; print(pkg_resources.get_distribution("volatility3").version)'
        )
        if installed:
            vol_exe_found = False
            try:
                probe = (
                    'import sysconfig, sys, os;'
                    'sd = sysconfig.get_path("scripts");'
                    'names = ["vol.exe", "vol3.exe"] if sys.platform == "win32" else ["vol", "vol3"];'
                    'print("FOUND" if any(os.path.exists(os.path.join(sd, n)) for n in names) else "NOTFOUND")'
                )
                probe_kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
                if platform.system() == 'Windows':
                    probe_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
                elif platform.system() == 'Darwin':
                    probe_kwargs.setdefault('encoding', 'utf-8')
                    probe_kwargs.setdefault('errors', 'replace')
                probe_kwargs['env'] = _get_clean_python_env()
                probe_kwargs['cwd'] = _get_safe_subprocess_cwd()
                probe_result = subprocess.run(
                    [python_cmd, '-c', probe], **probe_kwargs
                )
                if probe_result.returncode == 0 and 'FOUND' in (probe_result.stdout or ''):
                    vol_exe_found = True
            except Exception:
                vol_exe_found = False
            if not vol_exe_found:
                installed = False
                dependencies['volatility3']['error'] = (
                    'Python 包已装但 vol 命令缺失，请用 '
                    'pip install --force-reinstall volatility3==2.27.0 重装'
                )
        dependencies['volatility3']['installed'] = installed
        dependencies['volatility3']['version'] = version if version else ''
        if not installed and not dependencies['volatility3'].get('error'):
            dependencies['volatility3']['error'] = probe_errors.get('volatility3', '未安装')

        installed, version = check_dependency(
            'pycryptodome',
            'from Crypto.Cipher import AES',
            'from Crypto import __version__; print(__version__)'
        )
        dependencies['pycryptodome']['installed'] = installed
        dependencies['pycryptodome']['version'] = version if version else ''
        if not installed:
            dependencies['pycryptodome']['error'] = probe_errors.get('pycryptodome', '未安装')

        installed, version = check_dependency(
            'pypykatz',
            'import pypykatz',
            'import pkg_resources; print(pkg_resources.get_distribution("pypykatz").version)'
        )
        dependencies['pypykatz']['installed'] = installed
        dependencies['pypykatz']['version'] = version if version else ''
        if not installed:
            dependencies['pypykatz']['error'] = probe_errors.get('pypykatz', '未安装')

        installed, version = check_dependency(
            'openai',
            'from openai import OpenAI',
            'import importlib.metadata as m; print(m.version("openai"))'
        )
        dependencies['openai']['installed'] = installed
        dependencies['openai']['version'] = version if version else ''
        if not installed:
            dependencies['openai']['error'] = probe_errors.get(
                'openai', '未安装，AI 助手将使用 requests 兼容模式'
            )

        logger.info(f"依赖检测结果: {dependencies}")
        return dependencies

    def _check_plugin_dependencies(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        import subprocess
        import platform

        is_frozen = getattr(sys, 'frozen', False)
        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_macos_app = '.app/Contents/MacOS' in (sys.executable or '') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and '.app/Contents/MacOS' in sys.argv[0]
        )
        is_packaged = is_frozen or is_nuitka or is_macos_app

        if self._python_path:
            python_cmd = self._python_path
        else:
            system = platform.system()
            if is_packaged:
                if system == 'Windows':
                    python_cmd = 'python'
                else:
                    python_cmd = 'python3'
                import shutil as _shutil3
                resolved = _shutil3.which(python_cmd)
                if resolved:
                    python_cmd = resolved
            else:
                python_cmd = sys.executable

        def check_system_dependency(package_name: str, import_statement: str) -> bool:
            import os as _os2
            subprocess_kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
            if platform.system() == 'Windows':
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            elif platform.system() == 'Darwin':
                subprocess_kwargs.setdefault('encoding', 'utf-8')
                subprocess_kwargs.setdefault('errors', 'replace')
            clean_env = _get_clean_python_env()
            subprocess_kwargs['env'] = clean_env
            subprocess_kwargs['cwd'] = _get_safe_subprocess_cwd()

            try:
                result = subprocess.run(
                    [python_cmd, '-c', import_statement],
                    **subprocess_kwargs
                )
                return result.returncode == 0
            except Exception as e:
                logger.warning(f"检查依赖 {package_name} 时出错: {e}")
                return False

        crypto_plugins = ['hashdump', 'lsadump', 'cachedump']
        if plugin_id in crypto_plugins:
            if is_packaged or self._python_path:
                has_crypto = check_system_dependency('pycryptodome', 'from Crypto.Cipher import AES')
            else:
                try:
                    from Crypto.Cipher import AES
                    has_crypto = True
                except ImportError:
                    has_crypto = False

            if not has_crypto:
                error_msg = (
                    f"插件 '{plugin_id}' 需要 pycryptodome 库支持。\n\n"
                    "请点击下方按钮一键安装，或在命令行运行：\n"
                    "    pip install pycryptodome\n\n"
                    "安装后重新执行插件即可使用。"
                )
                logger.error(f"依赖检测失败: pycryptodome 未安装")
                return {
                    'success': False,
                    'error': error_msg,
                    'error_type': 'dependency_missing',
                    'missing_dependency': 'pycryptodome',
                    'data': []
                }

        pypykatz_plugins = ['pypykatz', 'pypykatz_internal']
        if plugin_id in pypykatz_plugins:
            if is_packaged or self._python_path:
                has_pypykatz = check_system_dependency('pypykatz', 'from pypykatz.pypykatz import pypykatz')
            else:
                try:
                    from pypykatz.pypykatz import pypykatz
                    has_pypykatz = True
                except ImportError:
                    has_pypykatz = False

            if not has_pypykatz:
                error_msg = (
                    f"插件 '{plugin_id}' 需要 pypykatz 库支持。\n\n"
                    "请点击下方按钮一键安装，或在命令行运行：\n"
                    "    pip install pypykatz\n\n"
                    "注意：Windows ARM64 平台可能需要安装 Rust 工具链或使用 x64 Python。"
                )
                logger.error(f"依赖检测失败: pypykatz 未安装")
                return {
                    'success': False,
                    'error': error_msg,
                    'error_type': 'dependency_missing',
                    'missing_dependency': 'pypykatz',
                    'data': []
                }

        return None

    @staticmethod
    def normalize_plugin_id(plugin_id: str) -> str:
        return normalize_plugin_id(plugin_id)

    def run_plugin(self, plugin_id: str, params: Dict = None, symbol_file_path: str = None) -> Dict[str, Any]:
        requested_plugin_id = plugin_id
        plugin_id = self.normalize_plugin_id(plugin_id)
        if plugin_id != requested_plugin_id:
            logger.info(f"归一化插件 ID: {requested_plugin_id} -> {plugin_id}")
        logger.info(f"执行插件: {plugin_id}")

        dependency_error = self._check_plugin_dependencies(plugin_id)
        if dependency_error:
            return dependency_error

        plugin_map = PLUGIN_MAP

        volatility_plugin = plugin_map.get(plugin_id)
        if not volatility_plugin:
            logger.warning(f"未知插件: {plugin_id}")
            return {
                'plugin': plugin_id,
                'timestamp': datetime.now().isoformat(),
                'image': self.image_name,
                'results': [],
                'error': f'插件 {plugin_id} 未实现'
            }

        extra_args = []
        if params:
            for key, value in params.items():
                extra_args.extend([f'--{key}', str(value)])

        if plugin_id == 'eventlog' and not any('--pattern' in str(arg) for arg in extra_args):
            extra_args.extend(['--pattern', r'\.(evt|evtx)$'])

        results = self._run_volatility(volatility_plugin, extra_args, symbol_file_path=symbol_file_path)

        info_msg = None
        pypykatz_available = False

        if plugin_id == 'hashdump' and results:
            logger.info("hashdump执行完成，自动获取明文密码...")

            is_frozen = getattr(sys, 'frozen', False)
            is_nuitka = hasattr(sys, 'nuitka_version') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
            )
            is_macos_app = '.app/Contents/MacOS' in (sys.executable or '') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and '.app/Contents/MacOS' in sys.argv[0]
            )
            is_packaged = is_frozen or is_nuitka or is_macos_app

            pypykatz_available = False
            if is_packaged or self._python_path:
                import subprocess
                try:
                    if self._python_path:
                        check_python = self._python_path
                    elif is_packaged:
                        check_python = 'python3' if platform.system() != 'Windows' else 'python'
                        import shutil as _shutil4
                        resolved = _shutil4.which(check_python)
                        if resolved:
                            check_python = resolved
                    else:
                        check_python = sys.executable
                    subprocess_kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
                    if platform.system() == 'Windows':
                        subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
                    elif platform.system() == 'Darwin':
                        subprocess_kwargs.setdefault('encoding', 'utf-8')
                        subprocess_kwargs.setdefault('errors', 'replace')
                    clean_env = _get_clean_python_env()
                    subprocess_kwargs['env'] = clean_env
                    subprocess_kwargs['cwd'] = _get_safe_subprocess_cwd()
                    result = subprocess.run(
                        [check_python, '-c', 'from pypykatz.pypykatz import pypykatz'],
                        **subprocess_kwargs
                    )
                    pypykatz_available = result.returncode == 0
                except Exception as e:
                    logger.warning(f"检测 pypykatz 时出错: {e}")
                    pypykatz_available = False
            else:
                try:
                    from pypykatz.pypykatz import pypykatz
                    pypykatz_available = True
                except ImportError:
                    pypykatz_available = False
                except Exception as e:
                    logger.warning(f"pypykatz 导入失败: {e}")
                    pypykatz_available = False

            if not pypykatz_available:
                logger.info("pypykatz 库未安装，跳过明文密码提取")

            if pypykatz_available:
                try:
                    pypykatz_results = self._run_volatility(
                        'pypykatz_plugin.PypykatzPlugin',
                        [],
                        symbol_file_path=symbol_file_path
                    )

                    if pypykatz_results and not (isinstance(pypykatz_results, list) and pypykatz_results and pypykatz_results[0].get('_error')):
                        password_map = {}  
                        for item in pypykatz_results:
                            username = item.get('username', '')
                            credtype = item.get('credtype', '')
                            password = item.get('password', '')

                            if credtype == 'wdigest' and password and password.strip():
                                if username not in password_map:
                                    password_map[username] = password

                        for item in results:
                            username = item.get('username', '')
                            if username in password_map:
                                item['plaintext_password'] = password_map[username]
                            else:
                                item['plaintext_password'] = ''

                        if password_map:
                            logger.info(f"成功合并明文密码，找到{len(password_map)}个用户的明文密码")
                    else:
                        for item in results:
                            item['plaintext_password'] = ''
                except Exception as e:
                    logger.warning(f"获取明文密码失败: {e}")
                    for item in results:
                        item['plaintext_password'] = ''
            else:
                for item in results:
                    item['plaintext_password'] = ''
                info_msg = "提示：安装 pypykatz 后可自动提取明文密码 (pip install pypykatz)"

        result_dict = {
            'plugin': plugin_id,
            'plugin_full_name': volatility_plugin,
            'timestamp': datetime.now().isoformat(),
            'image': self.image_name,
            'results': results
        }

        if info_msg:
            result_dict['_info'] = info_msg

        if plugin_id == 'hashdump' and not pypykatz_available:
            result_dict['_suggest_install'] = 'pypykatz'

        return result_dict

    def search_strings(self, patterns: List[str]) -> List[Dict]:
        results = []
        import platform
        import re
        import shutil

        logger.info(f"开始搜索字符串，内存镜像: {self.image_path}")
        logger.info(f"符号表目录: {self._symbols_dir}")
        logger.info(f"搜索模式: {patterns}")

        if platform.system() == 'Windows':
            strings_exe = None

            possible_paths = [
                self._symbols_dir.parent / 'strings.exe',  
                Path(os.path.dirname(sys.executable)) / 'strings.exe',  
            ]

            logger.info(f"检查 strings.exe 路径:")
            for path in possible_paths:
                logger.info(f"  - {path} (存在: {path.exists()})")
                if path.exists():
                    strings_exe = str(path)
                    break

            if not strings_exe:
                has_strings = shutil.which('strings') is not None
                logger.info(f"  - PATH 中的 strings: {has_strings}")
                if has_strings:
                    strings_exe = shutil.which('strings')

            if not strings_exe:
                logger.warning("未找到 strings.exe，将使用 Python 降级方案（速度较慢）")

            if strings_exe:
                logger.info(f"使用 strings 命令搜索内存（Windows + strings: {strings_exe}）")
                try:
                    import subprocess

                    logger.info(f"使用 strings + Python 正则匹配")

                    subprocess_kwargs = self._get_subprocess_kwargs(
                        capture_output=True,
                        timeout=600  
                    )
                    result = subprocess.run([strings_exe, '-n', '4', self.image_path], **subprocess_kwargs)

                    logger.info(f"命令返回码: {result.returncode}")
                    if result.stderr:
                        stderr_str = result.stderr.decode('ascii', errors='ignore')[:500]
                        if stderr_str.strip():
                            logger.warning(f"stderr: {stderr_str}")

                    if result.stdout and len(result.stdout) > 0:
                        try:
                            output = result.stdout.decode('ascii', errors='ignore')
                        except:
                            output = result.stdout.decode('latin-1', errors='ignore')

                        lines = output.split('\n')
                        logger.info(f"处理 {len(lines)} 行，开始匹配...")
                        for i, line in enumerate(lines):
                            line = line.strip()
                            if not line:
                                continue
                            for pattern in patterns:
                                try:
                                    regex = re.compile(pattern, re.IGNORECASE)
                                    if regex.search(line):
                                        results.append({
                                            'offset': f'line_{i}',
                                            'matched_string': line,
                                            'context': line[:100]
                                        })
                                        break
                                except re.error:
                                    logger.warning(f"无效的正则表达式: {pattern}")
                        logger.info(f"搜索完成: 找到 {len(results)} 个匹配")
                except Exception as e:
                    logger.error(f"strings 命令执行异常: {str(e)}")
            else:
                logger.info("使用 Python 读取内存文件（Windows，无 strings 命令）")
                try:
                    with open(self.image_path, 'rb') as f:
                        data = f.read()
                        strings_list = re.findall(b'[\\x20-\\x7e]{4,}', data)

                    logger.info(f"找到 {len(strings_list)} 个字符串，开始匹配模式...")

                    for i, s in enumerate(strings_list):
                        try:
                            line = s.decode('ascii', errors='ignore')
                        except:
                            continue

                        for pattern in patterns:
                            try:
                                regex = re.compile(pattern, re.IGNORECASE)
                                if regex.search(line):
                                    results.append({
                                        'offset': f'found_{i}',
                                        'matched_string': line,
                                        'context': line[:100]
                                    })
                                    break
                            except re.error:
                                logger.warning(f"无效的正则表达式: {pattern}")

                    logger.info(f"搜索完成: 检查了 {len(strings_list)} 个字符串，找到 {len(results)} 个匹配")

                except Exception as e:
                    logger.error(f"读取内存文件失败: {str(e)}")
        else:
            logger.info("使用 strings 命令搜索内存（Linux/macOS）")
            try:
                import subprocess

                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True,
                    text=True,
                    encoding='utf-8',  
                    errors='replace',  
                    timeout=120  
                )
                result = subprocess.run(['strings', '-n', '4', self.image_path], **subprocess_kwargs)

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    total_lines = len(lines)

                    for i, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            continue

                        for pattern in patterns:
                            try:
                                regex = re.compile(pattern, re.IGNORECASE)
                                if regex.search(line):
                                    results.append({
                                        'offset': f'line_{i}',
                                        'matched_string': line,
                                        'context': line[:100]
                                    })
                                    break  
                            except re.error:
                                logger.warning(f"无效的正则表达式: {pattern}")

                    logger.info(f"搜索完成: 检查了 {total_lines} 行，找到 {len(results)} 个匹配")
                else:
                    logger.error(f"strings 命令失败: {result.stderr}")

            except subprocess.TimeoutExpired:
                logger.error("字符串搜索超时")
            except Exception as e:
                logger.error(f"字符串搜索失败: {str(e)}")

        return results

    def dump_process(self, pid: int, output_dir: str, source_plugin: str = None) -> Dict:
        try:
            logger.info(f"开始转储进程 {pid}")

            os_type = self._detect_os_for_dump()
            source_plugin_lower = str(source_plugin or '').strip().lower()
            is_windows_psscan = (
                os_type == 'Windows' and source_plugin_lower.endswith('psscan')
            )
            export_type = 'process_memory'

            if os_type == 'macOS':
                plugin_name = 'mac.proc_maps.Maps'
                extra_args = ['--pid', str(pid), '--dump']
                export_type = 'process_memory_regions'
                logger.info(f"使用 macOS 插件: {plugin_name}")
            elif os_type == 'Linux':
                plugin_name = 'linux.proc.Maps'
                extra_args = ['--pid', str(pid), '--dump']
                export_type = 'process_memory_regions'
                logger.info(f"使用 Linux 插件: {plugin_name}")
            elif is_windows_psscan:
                plugin_name = 'windows.psscan.PsScan'
                extra_args = ['--pid', str(pid), '--dump']
                export_type = 'process_executable'
                logger.info(f"使用 Windows psscan PE 提取插件: {plugin_name}")
            elif os_type == 'Windows':
                plugin_name = 'windows.memmap.Memmap'
                extra_args = ['--pid', str(pid), '--dump']
                logger.info(f"使用 Windows 插件: {plugin_name}")
            else:
                return {
                    'pid': pid,
                    'os_type': os_type,
                    'status': 'unsupported',
                    'error': f'无法确定镜像系统类型，已停止进程转储（当前: {os_type}）',
                }

            export = self._run_volatility_export(
                plugin_name,
                extra_args,
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                fallback = (
                    '进程可执行文件提取命令执行失败'
                    if export_type == 'process_executable'
                    else '进程转储命令执行失败'
                )
                failure = self._export_failure(run, fallback)
                failure.update({
                    'pid': pid,
                    'os_type': os_type,
                    'export_type': export_type,
                    'source_plugin': source_plugin,
                })
                return failure

            output_files = []

            if export_type == 'process_executable':
                pattern = re.compile(
                    rf'^{re.escape(str(pid))}\..+\.dmp(?:-\d+)?$',
                    re.IGNORECASE,
                )
                output_files = [
                    str(path) for path in export['files'] if pattern.match(path.name)
                ]
            elif os_type == 'Windows':
                pattern = re.compile(rf'^pid\.{re.escape(str(pid))}(?:-\d+)?\.dmp$', re.IGNORECASE)
                output_files = [str(path) for path in export['files'] if pattern.match(path.name)]
            else:
                prefix = f'pid.{pid}.'
                output_files = [
                    str(path) for path in export['files']
                    if path.name.startswith(prefix) and path.name.lower().endswith('.dmp')
                ]

            if output_files:
                total_size = sum(os.path.getsize(f) for f in output_files)
                action_name = (
                    '主程序 PE 提取'
                    if export_type == 'process_executable'
                    else '进程转储'
                )
                logger.info(
                    f"进程 {pid} {action_name}成功，生成 {len(output_files)} 个文件，"
                    f"总大小: {total_size / 1024 / 1024:.2f} MB"
                )

                return {
                    'pid': pid,
                    'os_type': os_type,
                    'source_plugin': source_plugin,
                    'export_type': export_type,
                    'is_full_memory': export_type == 'process_memory',
                    'output_files': output_files,
                    'count': len(output_files),
                    'total_size': total_size,
                    'status': 'success'
                }
            else:
                if export_type == 'process_executable':
                    error = (
                        f'PID {pid} 由 psscan 物理扫描发现，但无法重建主程序 PE。'
                        '该进程的 PEB、页表或可执行文件内存页可能已损坏或缺失。'
                    )
                else:
                    error = run.get('stderr') or '转储文件未生成'
                return {
                    'pid': pid,
                    'os_type': os_type,
                    'status': 'failed',
                    'error': error,
                    'source_plugin': source_plugin,
                    'export_type': export_type,
                }

        except Exception as e:
            logger.error(f"进程转储失败: {str(e)}")
            return {
                'pid': pid,
                'status': 'error',
                'error': str(e)
            }

    def _detect_os_from_banner(self, banner_output: str) -> str:
        try:
            for line in banner_output.split('\n'):
                if 'Volatility 3' in line or 'Progress' in line:
                    continue
                line_lower = line.lower()
                if 'darwin' in line_lower or 'macos' in line_lower:
                    return 'Mac'
                elif 'linux' in line_lower:
                    return 'Linux'
                elif 'windows' in line_lower or 'microsoft' in line_lower:
                    return 'Windows'
            return 'Unknown'
        except Exception as e:
            logger.warning(f"从 banner 检测 OS 失败: {str(e)}")
            return 'Unknown'

    def _detect_os_for_dump(self) -> str:
        if self._detected_os is not None:
            return self._detected_os

        try:
            result = self._run_volatility_raw('banners.Banners')
            for line in result.split('\n'):
                if 'Volatility 3' in line:
                    continue
                if 'Darwin' in line or 'macOS' in line:
                    self._detected_os = 'macOS'
                    return 'macOS'
                elif 'Windows' in line or 'Microsoft' in line:
                    self._detected_os = 'Windows'
                    return 'Windows'
                elif 'Linux' in line:
                    self._detected_os = 'Linux'
                    return 'Linux'
            self._detected_os = 'Unknown'
            return 'Unknown'
        except Exception as e:
            logger.warning(f"OS 检测失败: {str(e)}")
            return 'Unknown'


    def extract_file(self, offset: str, output_dir: str) -> Dict:
        try:
            os_type = self._detect_os_for_dump()

            if os_type == 'macOS':
                return {
                    'status': 'unsupported',
                    'error': 'macOS 不支持文件提取（只能列出文件）'
                }

            if os_type == 'Linux':
                return self._extract_linux_file(offset, output_dir)

            if os_type != 'Windows':
                return {
                    'status': 'unsupported',
                    'error': f'无法为当前镜像选择文件提取插件（当前: {os_type}）',
                }

            logger.info(f"开始提取文件 @ {offset}")

            address_modes = (
                ('virtual', '--virtaddr'),
                ('physical', '--physaddr'),
            )
            attempted_modes = []
            failures = []

            for address_type, address_flag in address_modes:
                attempted_modes.append(address_type)
                export = self._run_volatility_export(
                    'windows.dumpfiles.DumpFiles',
                    [address_flag, offset],
                    output_dir,
                    use_symbols=True,
                    renderer='json',
                )
                run = export['run']
                run_status = run.get('status')

                if run_status in ('cancelled', 'timeout'):
                    failure = self._export_failure(run, '文件提取命令执行失败')
                    failure['attempted_address_types'] = attempted_modes
                    return failure

                if run_status != 'success':
                    failures.append(
                        f"{address_type}: {run.get('error') or run.get('stderr') or '命令执行失败'}"
                    )
                    continue

                extracted_files = []
                for path in export['files']:
                    filename = path.name
                    if not filename.startswith('file.'):
                        continue
                    try:
                        file_size = path.stat().st_size
                        extracted_files.append({
                            'file': filename,
                            'path': str(path),
                            'size': file_size,
                        })
                        logger.info(f"提取成功: {filename} ({file_size} 字节)")
                    except Exception as e:
                        logger.warning(f"处理文件失败: {str(e)}")

                if not extracted_files:
                    logger.info(
                        "DumpFiles 按 %s 地址提取无产物，尝试下一地址类型",
                        address_type,
                    )
                    continue

                extracted_files.sort(key=lambda item: item['size'], reverse=True)
                return {
                    'status': 'success',
                    'file': extracted_files[0]['file'],
                    'path': extracted_files[0]['path'],
                    'size': extracted_files[0]['size'],
                    'output_files': extracted_files,
                    'address_type': address_type,
                    'attempted_address_types': attempted_modes,
                }

            error = '文件提取失败：已尝试虚拟地址和物理地址，均未生成文件。该文件对象的缓存数据可能已不在镜像中。'
            if failures:
                error += ' ' + ' | '.join(failures)
            return {
                'status': 'failed',
                'error': error,
                'attempted_address_types': attempted_modes,
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def _extract_linux_file(self, inode_addr: str, output_dir: str) -> Dict:
        try:
            logger.info(f"开始提取 Linux 文件 @ inode {inode_addr}")

            extra_args = ['--inode', inode_addr, '--dump']
            export = self._run_volatility_export(
                'linux.pagecache.InodePages',
                extra_args,
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, 'Linux 页缓存文件提取命令执行失败')

            extracted_files = []
            for path in export['files']:
                filename = path.name
                if filename.startswith('inode_') and filename.endswith('.dmp'):
                    try:
                        file_path = str(path)
                        file_size = path.stat().st_size

                        extracted_files.append({
                            'file': filename,
                            'path': file_path,
                            'size': file_size
                        })

                        logger.info(f"提取成功: {filename} ({file_size} 字节)")
                        break  

                    except Exception as e:
                        logger.warning(f"处理文件失败: {str(e)}")

            if not extracted_files:
                return {
                    'status': 'failed',
                    'error': '文件提取失败，未找到提取的文件'
                }

            return {
                'status': 'success',
                'file': extracted_files[0]['file'],
                'path': extracted_files[0]['path'],
                'size': extracted_files[0]['size']
            }

        except Exception as e:
            logger.error(f"提取 Linux 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_dll(self, pid: int, base: str, output_dir: str) -> Dict:
        try:
            logger.info(f"开始提取 DLL - PID: {pid}, Base: {base}")

            os_type = self._detect_os_for_dump()
            if os_type != 'Windows':
                return {
                    'status': 'unsupported',
                    'error': f'DLL 提取仅支持 Windows 镜像（当前: {os_type}）',
                }

            extra_args = ['--pid', str(pid), '--base', base]
            export = self._run_volatility_export(
                'windows.pedump.PEDump',
                extra_args,
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, 'DLL 提取命令执行失败')

            for path in export['files']:
                filename = path.name
                if filename.startswith('PE.') and f'.{pid}.' in filename:
                    try:
                        safe_base = base.replace('0x', '').lower()
                        new_name = f'dll.{pid}.{safe_base}.dmp'
                        new_path = self._unique_output_path(Path(output_dir) / new_name)

                        path.rename(new_path)

                        file_size = new_path.stat().st_size
                        logger.info(f"DLL提取成功: {new_path.name} ({file_size} 字节)")

                        return {
                            'status': 'success',
                            'file': new_path.name,
                            'path': str(new_path),
                            'size': file_size
                        }

                    except Exception as e:
                        logger.warning(f"重命名文件失败: {str(e)}")

            return {
                'status': 'failed',
                'error': 'DLL提取失败'
            }

        except Exception as e:
            logger.error(f"提取DLL失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_pagecache_file(self, file_path: str, save_path: str) -> Dict:
        try:
            logger.info(f"开始提取页缓存文件: {file_path} -> {save_path}")

            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'页缓存文件提取仅支持 Linux 镜像（当前: {os_type}）',
                }

            save_dir = os.path.dirname(save_path)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)

            extra_args = ['--find', file_path, '--dump']

            logger.info(f"运行命令: linux.pagecache.InodePages --find {file_path} --dump")

            export = self._run_volatility_export(
                'linux.pagecache.InodePages',
                extra_args,
                save_dir or str(Path(save_path).parent),
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, 'Linux 页缓存文件提取命令执行失败')

            logger.debug(f"插件输出:\n{run.get('stdout', '')[:1000] or '无输出'}...")

            import shutil

            possible_files = [
                path for path in export['files']
                if path.name.startswith('inode_') and path.name.endswith('.dmp')
            ]

            if possible_files:
                extracted_file = possible_files[0]
                final_path = self._unique_output_path(Path(save_path))

                shutil.move(str(extracted_file), str(final_path))

                file_size = final_path.stat().st_size
                logger.info(f"页缓存文件提取成功: {file_path} -> {final_path} ({file_size} 字节)")
                return {
                    'status': 'success',
                    'file': str(final_path),
                    'size': file_size
                }
            else:
                logger.warning(f"文件提取失败，本次命令没有生成 inode .dmp 文件")
                logger.warning(f"插件输出: {run.get('stdout', '')}")
                return {
                    'status': 'failed',
                    'error': '文件提取失败，未找到输出文件（可能文件不在页缓存中）'
                }

        except Exception as e:
            logger.error(f"提取页缓存文件失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_elf_files(self, pid: int = None, output_dir: str = None) -> Dict:
        try:
            if output_dir is None:
                output_dir = os.getcwd()

            logger.info(f"开始提取 ELF 文件" + (f" (PID: {pid})" if pid else ""))

            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'ELF 文件提取仅支持 Linux 系统（当前: {os_type}）'
                }

            extra_args = ['--dump']
            if pid is not None:
                extra_args.extend(['--pid', str(pid)])

            export = self._run_volatility_export(
                'linux.elfs.Elfs',
                extra_args,
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, 'ELF 文件提取命令执行失败')

            extracted_files = []
            pattern = f'pid.{pid}.' if pid else 'pid.'

            for path in export['files']:
                filename = path.name
                if filename.startswith(pattern) and filename.endswith('.dmp'):
                    try:
                        file_path = str(path)
                        file_size = path.stat().st_size

                        parts = filename.replace('.dmp', '').split('.')
                        file_pid = parts[1] if len(parts) > 1 else 'unknown'
                        file_comm = parts[2] if len(parts) > 2 else 'unknown'
                        file_addr = parts[3] if len(parts) > 3 else 'unknown'

                        extracted_files.append({
                            'file': filename,
                            'path': file_path,
                            'size': file_size,
                            'pid': file_pid,
                            'name': file_comm,
                            'address': file_addr
                        })

                        logger.info(f"ELF文件提取成功: {filename} ({file_size} 字节)")

                    except Exception as e:
                        logger.warning(f"处理文件失败 {filename}: {str(e)}")

            if not extracted_files:
                return {
                    'status': 'failed',
                    'error': '未找到 ELF 文件'
                }

            total_size = sum(f['size'] for f in extracted_files)
            return {
                'status': 'success',
                'count': len(extracted_files),
                'total_size': total_size,
                'files': extracted_files[:10]  
            }

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_elf_file(self, pid: int, start: str, file_name: str, output_dir: str) -> Dict:
        try:
            logger.info(f"开始提取单个 ELF 文件 - PID: {pid}, Start: {start}, Name: {file_name}")

            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'ELF 文件提取仅支持 Linux 镜像（当前: {os_type}）',
                }

            extra_args = ['--dump', '--pid', str(pid)]
            export = self._run_volatility_export(
                'linux.elfs.Elfs',
                extra_args,
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, '单个 ELF 提取命令执行失败')

            safe_name = file_name.replace('/', '_').replace('\\', '_')
            safe_start = start.lower().replace('0x', '')

            requested_address = int(str(start), 0)
            address_pattern = re.compile(
                rf'^pid\.{re.escape(str(pid))}\..*\.0x{requested_address:x}(?:-\d+)?\.dmp$',
                re.IGNORECASE,
            )

            for path in export['files']:
                filename = path.name
                if address_pattern.match(filename):
                    try:
                        new_name = f'elf.{pid}.{safe_name}.{safe_start}.dmp'
                        new_path = self._unique_output_path(Path(output_dir) / new_name)

                        path.rename(new_path)

                        file_size = new_path.stat().st_size
                        logger.info(f"单个 ELF 文件提取成功: {new_path.name} ({file_size} 字节)")

                        return {
                            'status': 'success',
                            'output_path': str(new_path),
                            'file': new_path.name,
                            'size': file_size
                        }

                    except Exception as e:
                        logger.warning(f"处理文件失败 {filename}: {str(e)}")

            return {
                'status': 'failed',
                'error': f'未找到匹配的 ELF 文件 (PID: {pid}, Start: {start})'
            }

        except Exception as e:
            logger.error(f"提取单个 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_lsof_file(self, file_path: str, plugin_id: str, output_dir: str) -> Dict:
        try:
            logger.info(f"开始提取 lsof 文件: {file_path}")

            os_type = self._detect_os_for_dump()
            if plugin_id == 'mac_lsof' or os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': (
                        'lsof 文件提取依赖 Linux 页缓存，'
                        f'不支持当前镜像（当前: {os_type}）'
                    ),
                }

            file_name = os.path.basename(file_path) if file_path else 'unknown'
            safe_name = file_name.replace('/', '_').replace('\\', '_')
            save_path = os.path.join(output_dir, f'lsof_{safe_name}')

            result = self.extract_pagecache_file(file_path, save_path)

            if result['status'] == 'success':
                return {
                    'status': 'success',
                    'output_path': result['file'],
                    'file': os.path.basename(result['file']),
                    'size': result['size']
                }
            else:
                return result

        except Exception as e:
            logger.error(f"提取 lsof 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_lsof_files(self, plugin_id: str, output_dir: str) -> Dict:
        return {
            'status': 'unsupported',
            'error': '批量提取 lsof 文件暂不支持，请使用单个文件下载'
        }

    def dump_files(
        self,
        filter_pattern: str = None,
        ignore_case: bool = False,
        pid: int = None,
        output_dir: str = None
    ) -> Dict:
        try:
            if output_dir is None:
                output_dir = os.getcwd()

            logger.info(f"开始提取页缓存文件")

            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'文件提取仅支持 Linux 系统（当前: {os_type}）'
                }

            if filter_pattern or pid is not None:
                return {
                    'status': 'unsupported',
                    'error': (
                        '当前 Volatility 的 linux.pagecache.RecoverFs 不支持按正则或 PID '
                        '过滤恢复。请在页缓存列表中单个提取，或恢复完整文件系统归档。'
                    ),
                }

            export = self._run_volatility_export(
                'linux.pagecache.RecoverFs',
                [],
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, 'Linux 页缓存文件系统恢复失败')

            extracted_files = []
            for path in export['files']:
                if not path.name.startswith('recovered_fs.tar.'):
                    continue
                file_size = path.stat().st_size
                extracted_files.append({
                    'file': path.name,
                    'path': str(path),
                    'size': file_size,
                    'type': 'filesystem_archive',
                })

            if not extracted_files:
                return {
                    'status': 'failed',
                    'error': '恢复命令已结束，但本次没有生成文件系统归档',
                }

            total_size = sum(item['size'] for item in extracted_files)
            return {
                'status': 'success',
                'count': len(extracted_files),
                'total_size': total_size,
                'files': extracted_files,
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def dump_certificates(self, output_dir: str) -> Dict:
        try:
            logger.info("===== 开始导出 Windows 注册表证书 =====")

            os_type = self._detect_os_for_dump()
            if os_type != 'Windows':
                return {
                    'status': 'unsupported',
                    'error': f'注册表证书导出仅支持 Windows 镜像（当前: {os_type}）',
                }

            plugin_name = 'windows.registry.certificates.Certificates'
            logger.info(f"使用插件: {plugin_name} with --dump")
            export = self._run_volatility_export(
                plugin_name,
                ['--dump'],
                output_dir,
                use_symbols=True,
            )
            run = export['run']
            if run.get('status') != 'success':
                return self._export_failure(run, '证书导出命令执行失败')

            extracted_files = []
            for path in export['files']:
                filename = path.name
                if filename.lower().endswith(('.crt', '.cer')) or filename.lower().startswith('certificate'):
                    extracted_files.append({
                        'file': filename,
                        'path': str(path),
                        'size': path.stat().st_size,
                    })

            total_size = sum(item['size'] for item in extracted_files)
            logger.info(f"证书导出完成，本次生成 {len(extracted_files)} 个文件")
            return {
                'status': 'success',
                'count': len(extracted_files),
                'total_size': total_size,
                'output_dir': str(Path(output_dir).resolve()),
                'files': extracted_files,
            }

        except Exception as e:
            logger.error(f"导出证书失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def detect_image_info(self) -> Dict:
        try:
            result = self._run_volatility('windows.info.Info')

            if result and len(result) > 0:
                info_map = {}
                for row in result:
                    key = row.get('variable', '').strip()
                    val = row.get('value', '').strip()
                    if key:
                        info_map[key] = val

                return {
                    'format': 'raw',
                    'os': 'Windows',
                    'os_version': info_map.get('NTBuildLab', info_map.get('Major/Minor', 'Unknown')),
                    'architecture': 'x64' if info_map.get('Is64Bit') == 'True' else 'x86',
                    'kernel_version': info_map.get('CSDVersion', ''),
                    'system_time': info_map.get('SystemTime', datetime.now().isoformat()),
                    'kernel_base': info_map.get('Kernel Base', ''),
                    'dtb': info_map.get('DTB', ''),
                    'pe_timestamp': info_map.get('PE TimeDateStamp', '')
                }

        except Exception as e:
            logger.error(f"镜像信息检测失败: {str(e)}")

        return {
            'format': 'raw',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'architecture': 'Unknown',
            'kernel_version': 'Unknown',
            'system_time': datetime.now().isoformat()
        }
