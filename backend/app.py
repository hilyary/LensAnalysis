import sys
import os
import logging
import logging.handlers
from pathlib import Path
from threading import Thread
import json
import platform
from datetime import datetime
from typing import Dict, Tuple


import webview

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.api.handlers import APIHandler


PYPYKATZ_PLUGIN_CODE = '''
"""
pypykatz_plugin.py - Volatility 3 自定义插件
使用 pypykatz 库从 Windows 内存中提取明文密码
"""

import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

from pypykatz.pypykatz import pypykatz as pparser

vollog = logging.getLogger(__name__)


class PypykatzPlugin(interfaces.plugins.PluginInterface):
    """使用 pypykatz 提取 Windows 凭证（包括明文密码）"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", description="Windows kernel symbols"
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(3, 0, 0)
            ),
        ]

    def run(self):
        """执行 pypykatz 分析"""
        return pparser.go_volatility3(self)
'''


def is_packaged_runtime() -> bool:
    argv0 = str(sys.argv[0] or '') if getattr(sys, 'argv', None) else ''
    executable = str(sys.executable or '')
    return bool(
        getattr(sys, 'frozen', False)
        or hasattr(sys, 'nuitka_version')
        or '__compiled__' in globals()
        or hasattr(sys, '_nuitka_binary')
        or argv0.lower().endswith(('.exe', '.appimage'))
        or '.app/Contents/MacOS' in argv0
        or '.app/Contents/MacOS' in executable
    )


def get_executable_dir() -> Path:
    candidates = []
    if getattr(sys, 'argv', None) and sys.argv:
        candidates.append(Path(sys.argv[0]))
    if sys.executable:
        candidates.append(Path(sys.executable))

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved.is_file():
                return resolved.parent
            if resolved.is_dir():
                return resolved
        except Exception:
            continue
    return Path.cwd()


def extract_dropped_file_paths(event: object) -> list[str]:
    if not isinstance(event, dict):
        return []

    transfer = event.get('dataTransfer') or event.get('domTransfer') or {}
    files = transfer.get('files') if isinstance(transfer, dict) else None
    if not isinstance(files, (list, tuple)):
        return []

    paths: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        value = item.get('pywebviewFullPath') or item.get('path')
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = os.path.normpath(value.strip())
        if normalized not in paths:
            paths.append(normalized)
    return paths


def get_resource_root_candidates() -> list[Path]:
    candidates: list[Path] = []

    def add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path
        if resolved not in candidates:
            candidates.append(resolved)

    add(Path(__file__).parent.parent)
    add(Path(__file__).parent)

    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        add(Path(meipass))

    exe_dir = get_executable_dir()
    add(exe_dir)
    add(exe_dir / 'resources')
    add(exe_dir / '_internal')

    for parent in [exe_dir, *exe_dir.parents]:
        if parent.name == 'Contents':
            add(parent / 'Resources')
            add(parent / 'Resources' / 'app')
            break

    add(Path.cwd())
    return candidates


def resolve_frontend_index() -> Path:
    relative_candidates = [
        Path('frontend') / 'index.html',
        Path('index.html'),
        Path('app') / 'frontend' / 'index.html',
    ]

    checked = []
    for root in get_resource_root_candidates():
        for relative in relative_candidates:
            candidate = root / relative
            checked.append(str(candidate))
            if candidate.is_file():
                return candidate

    logger.error("前端文件查找失败，已检查路径:\n%s", "\n".join(checked))
    raise FileNotFoundError("找不到前端文件 frontend/index.html，请确认 Nuitka 打包时包含 frontend 目录")


def get_user_data_dir() -> Path:
    system = platform.system()

    if system == 'Windows':  
        if is_packaged_runtime():
            exe_dir = get_executable_dir()
        else:
            exe_dir = Path(__file__).parent.parent

        app_data = exe_dir / 'data'

        try:
            app_data.mkdir(parents=True, exist_ok=True)
            test_file = app_data / '.write_test'
            test_file.touch()
            test_file.unlink()
        except (OSError, PermissionError):
            app_data = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
            app_data.mkdir(parents=True, exist_ok=True)
    elif system == 'Darwin':  
        app_data = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
    else:  
        app_data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'LensAnalysis'

    return app_data


try:
    user_data_dir = get_user_data_dir()
    logs_dir = user_data_dir / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.handlers.RotatingFileHandler(
                logs_dir / 'app.log', maxBytes=1024*1024, backupCount=3, encoding='utf-8'
            ),
            logging.StreamHandler()
        ]
    )
except Exception as e:
    import tempfile
    user_data_dir = Path(tempfile.gettempdir()) / 'LensAnalysis'
    logs_dir = user_data_dir / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.handlers.RotatingFileHandler(
                logs_dir / 'app.log', maxBytes=1024*1024, backupCount=3, encoding='utf-8'
            ),
            logging.StreamHandler()
        ]
    )
    print(f"警告: 主数据目录无法访问，使用临时目录: {user_data_dir}")
    print(f"原始错误: {e}")

logger = logging.getLogger(__name__)


class LensAnalysisApp:

    def __init__(self):
        self.window = None
        self.api_handler = APIHandler()
        self.license_manager = None
        self.license_valid = True
        self.license_info = None
        self.show_welcome = not self.api_handler.has_user_profile()


        self._init_plugins()

        self._check_pypykatz_compatibility()

    def _init_plugins(self):
        try:
            user_plugins_dir = get_user_data_dir() / 'plugins'
            user_plugins_dir.mkdir(parents=True, exist_ok=True)

            plugin_file = user_plugins_dir / 'pypykatz_plugin.py'

            if not plugin_file.exists():
                logger.info(f"写入内置插件: {plugin_file}")
                with open(plugin_file, 'w', encoding='utf-8') as f:
                    f.write(PYPYKATZ_PLUGIN_CODE)
                logger.info(f"插件写入成功")
            else:
                logger.info(f"插件文件已存在: {plugin_file}")

        except Exception as e:
            logger.warning(f"初始化插件时出错: {e}")
            import traceback
            logger.warning(traceback.format_exc())

    def _check_pypykatz_compatibility(self):
        try:
            import subprocess

            is_frozen = getattr(sys, 'frozen', False)
            is_nuitka = hasattr(sys, 'nuitka_version') or (
                hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
            )
            is_packaged = is_frozen or is_nuitka

            if is_packaged:
                if platform.system() == 'Windows':
                    python_cmd = 'python'
                else:
                    python_cmd = 'python3'
            else:
                python_cmd = sys.executable

            system_python_version = None
            subprocess_kwargs = {'capture_output': True, 'text': True, 'timeout': 10}
            subprocess_kwargs['cwd'] = str(Path.home())
            if platform.system() == 'Windows':
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            elif platform.system() == 'Darwin':
                subprocess_kwargs.setdefault('encoding', 'utf-8')
                subprocess_kwargs.setdefault('errors', 'replace')

            try:
                version_result = subprocess.run(
                    [python_cmd, '--version'],
                    **subprocess_kwargs
                )
                version_output = version_result.stdout.strip() or version_result.stderr.strip()
                import re
                match = re.search(r'Python (\d+)\.(\d+)', version_output)
                if match:
                    system_python_version = (int(match.group(1)), int(match.group(2)))
            except Exception as e:
                logger.warning(f"无法获取系统 Python 版本: {e}")

            check_version = system_python_version if system_python_version else sys.version_info[:2]
            if check_version >= (3, 10):
                logger.info(f"Python {check_version[0]}.{check_version[1]}，跳过 pypykatz 兼容性检查")
                return

            if is_packaged:
                try:
                    pypykatz_kwargs = subprocess_kwargs.copy()
                    pypykatz_kwargs['timeout'] = 30
                    result = subprocess.run(
                        [python_cmd, '-c', 'import pypykatz; print(pypykatz.__file__)'],
                        **pypykatz_kwargs
                    )
                    if result.returncode != 0:
                        return
                    pypykatz_file = result.stdout.strip()
                    pypykatz_path = Path(pypykatz_file).parent
                except Exception:
                    return
            else:
                try:
                    import pypykatz
                    pypykatz_path = Path(pypykatz.__file__).parent
                except ImportError:
                    return

            vol3_reader_path = pypykatz_path / 'commons' / 'readers' / 'volatility3'

            if not vol3_reader_path.exists():
                return

            init_file = vol3_reader_path / '__init__.py'
            needs_fix = False
            if init_file.exists():
                content = init_file.read_text(encoding='utf-8')
                if 'from volatility.framework' in content:
                    needs_fix = True

            volreader_file = vol3_reader_path / 'volreader.py'
            if volreader_file.exists():
                content = volreader_file.read_text(encoding='utf-8')
                if "layer_name = self.vol_obj.config['primary']" in content:
                    needs_fix = True

            if needs_fix:
                logger.info("检测到 pypykatz 需要兼容性修复，正在修复...")
                from backend.api.handlers import APIHandler
                handler = APIHandler.__new__(APIHandler)
                handler._fix_pypykatz_compatibility()
                logger.info("pypykatz 兼容性修复完成")

        except Exception as e:
            logger.warning(f"检查 pypykatz 兼容性时出错: {e}")

    def start(self):
        logger.info("启动析镜 LensAnalysis...")
        self.api_handler.set_app(self)


        frontend_path = str(resolve_frontend_index())

        logger.info(f"前端路径: {frontend_path}")

        if not Path(frontend_path).exists():
            logger.error(f"前端文件不存在: {frontend_path}")
            raise FileNotFoundError(f"找不到前端文件: {frontend_path}")

        system = platform.system()
        is_windows = system == 'Windows'

        window_args = {
            'title': '析镜 LensAnalysis - 内存取证分析工具',
            'url': frontend_path,
            'js_api': self.api_handler,
            'resizable': True,
            'frameless': False,
            'background_color': '#ffffff'
        }

        window_args['width'] = 1400
        window_args['height'] = 850
        window_args['min_size'] = (1200, 700)


        if self.show_welcome:
            window_args['title'] = '析镜 - 欢迎'
            window_args['width'] = 1220
            window_args['height'] = 700
            window_args['min_size'] = (1220, 700)  
            window_args['resizable'] = False

        self.window = webview.create_window(**window_args)

        self.api_handler.set_window(self.window)

        start_kwargs = {'debug': False, 'http_server': True}
        if sys.platform == 'win32':
            start_kwargs['gui'] = 'edgechromium'
        if sys.platform == 'win32':
            webview.start(self._bind_file_drop, self.window, **start_kwargs)
        else:
            webview.start(**start_kwargs)

    def _bind_file_drop(self, window):
        try:
            from webview.dom import DOMEventHandler

            def on_drop(event):
                paths = extract_dropped_file_paths(event)
                if not paths:
                    return
                point = {
                    'x': event.get('clientX') if isinstance(event, dict) else None,
                    'y': event.get('clientY') if isinstance(event, dict) else None,
                }
                script = (
                    'window.app && window.app.handleAIDroppedFiles('
                    f'{json.dumps(paths, ensure_ascii=False)}, '
                    f'{json.dumps(point)});'
                )
                window.evaluate_js(script)

            document_events = window.dom.document.events
            document_events.dragenter += DOMEventHandler(
                lambda _event: None,
                prevent_default=True,
                stop_propagation=True,
            )
            document_events.dragover += DOMEventHandler(
                lambda _event: None,
                prevent_default=True,
                stop_propagation=True,
                debounce=120,
            )
            document_events.drop += DOMEventHandler(
                on_drop,
                prevent_default=True,
                stop_propagation=True,
            )
            window.evaluate_js(
                'window.app && window.app.enableAINativeFileDropVisuals();'
            )
            logger.info('桌面文件拖放桥接已启用')
        except Exception as exc:
            logger.warning(f'启用桌面文件拖放失败: {exc}')

    def _check_license(self):
        if self.license_manager is None:
            self.license_valid = True
            self.license_info = None
            return

        is_valid, message, license_info = self.license_manager.check_license()
        self.license_valid = is_valid
        self.license_info = license_info

        if is_valid:
            logger.info(f"许可证有效: {license_info.get('user', 'Unknown')}")
        else:
            logger.warning(f"许可证无效: {message}")

    def activate_license(self, license_key: str) -> Tuple[bool, str]:
        if self.license_manager is None:
            return True, '当前版本已开源，无需激活'

        success, message = self.license_manager.activate_license(license_key)

        if success:
            self._check_license()

        return success, message

    def get_license_status(self) -> Dict:
        if self.license_manager is None:
            return {'valid': True, 'open_source': True}

        is_valid, message, license_info = self.license_manager.check_license()

        logger.info("正在获取机器码...")
        machine_code = self.license_manager.get_machine_code()
        logger.info(f"机器码生成: {machine_code}")

        self.license_valid = is_valid
        self.license_info = license_info

        if is_valid and license_info:
            result = {
                'valid': True,
                'user': license_info.get('user', ''),
                'activated_at': license_info.get('activated_at', 0),
                'expiry': license_info.get('expiry', 0),
                'machine_code': machine_code
            }
            logger.info(f"返回许可证状态: {result}")
            return result

        result = {
            'valid': False,
            'machine_code': machine_code
        }
        logger.info(f"返回许可证状态（未激活）: {result}")
        return result

    def on_loaded(self):
        logger.info("前端页面加载完成")


def main():
    import sys
    import os
    import traceback

    try:
        if platform.system() == 'Darwin':
            display = os.environ.get('DISPLAY')
            logger.info(f"DISPLAY 环境变量: {display}")

            ssh_connection = os.environ.get('SSH_CONNECTION')
            if ssh_connection:
                logger.warning(f"检测到 SSH 连接，可能无法显示 GUI")

        logger.info("=" * 60)
        logger.info("LensAnalysis 启动")
        logger.info(f"Python executable: {sys.executable}")
        logger.info(f"sys.frozen: {getattr(sys, 'frozen', False)}")
        logger.info(f"Command line args: {sys.argv}")
        logger.info(f"Working directory: {os.getcwd()}")
        logger.info("=" * 60)

        try:
            import tempfile
            env_file = Path(tempfile.gettempdir()) / 'lensanalysis_env.txt'
            with open(env_file, 'w') as f:
                for key, value in sorted(os.environ.items()):
                    f.write(f"{key}={value}\n")
            logger.info(f"环境变量已记录到: {env_file}")
        except Exception as e:
            logger.warning(f"无法记录环境变量: {e}")

        try:
            import tempfile
            marker_file = Path(tempfile.gettempdir()) / 'lensanalysis_started.txt'
            marker_file.write_text(f"Started at: {datetime.now()}\nArgs: {sys.argv}\nDir: {os.getcwd()}\n")
            logger.info(f"启动标记文件已创建: {marker_file}")
        except Exception as e:
            logger.warning(f"无法创建启动标记: {e}")

        app = LensAnalysisApp()
        app.start()

    except Exception as e:
        error_msg = f"ERROR: {e}\n{traceback.format_exc()}"
        logger.error(error_msg)

        try:
            import tempfile
            error_file = Path(tempfile.gettempdir()) / 'lensanalysis_error.txt'
            error_file.write_text(error_msg)
        except:
            pass

        try:
            import tkinter
            root = tkinter.Tk()
            root.withdraw()
            tkinter.messagebox.showerror("LensAnalysis 启动失败", str(e))
        except:
            pass

        sys.exit(1)


if __name__ == '__main__':
    main()
