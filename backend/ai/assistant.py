from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .client import AIClientError, OpenAICompatibleClient
from .config import AIConfig

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """你是析镜 LensAnalysis 的内存取证助手。
你必须基于已加载镜像、插件缓存和可调用工具回答，不要编造不存在的取证结论。
如果用户要求加载、打开或切换内存镜像，应调用 request_load_image；如果用户给了本地镜像路径，应把路径放入 image_path，不要声称自己无法加载镜像。
如果用户要求打开文件、打开文件夹、打开报告、定位文件或显示所在目录，应调用 open_path 或 reveal_path。
优先复用缓存；如果需要执行插件，先说明你要执行的插件及原因。
如果用户要求导出、解密、dump 或提取文件/进程内存，可以通过 run_plugin 调用对应操作名并传入必要参数。
如果插件提示缺少、不匹配或无法加载符号表，应先调用 get_symbol_status 核对当前镜像，再调用 install_symbols_for_image 请求安装。默认自动安装；用户希望自己选择本地符号表时 method 使用 local。安装或打开文件选择器必须经过用户确认。
如果用户要求梳理时间线、按时间排序、还原攻击/使用过程，应调用 build_timeline。
如果用户提供题目描述、题干、提示或 Flag 格式，应先调用 build_analysis_plan 并结合缓存给出插件建议，不要自动批量执行插件。
取证分析需要保留原始证据，插件缓存中的密码、令牌、哈希、路径、聊天记录等字段不要擅自脱敏或改写。
涉及结论时尽量给出证据来源，例如插件名、缓存文件、记录序号或关键字段。
回答使用中文，结论要区分“已证实”“可疑”“需要进一步验证”。
"""


class ForensicsAIAssistant:

    def __init__(
        self,
        config: AIConfig,
        api_handler: Any,
        proxy_url: Optional[str] = None,
        allow_plugin_execution: bool = False,
    ):
        self.config = config
        self.api = api_handler
        self.client = OpenAICompatibleClient(config, proxy_url)
        self.allow_plugin_execution = allow_plugin_execution

    def chat(self, user_message: str, history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        user_message = (user_message or "").strip()
        if not user_message:
            return {"status": "error", "message": "请输入问题"}

        load_intent = re.search(r"(加载|打开|选择|导入|切换).{0,12}(内存)?镜像|内存镜像.{0,12}(加载|打开|选择|导入|切换)", user_message)
        image_path = _extract_image_path(user_message)
        if load_intent or image_path:
            result = self._tool_request_load_image({
                "os_type": _guess_os_type(user_message),
                "image_path": image_path or "",
            })
            return {
                "status": "success",
                "data": {
                    "message": result.get("message") or "确认后请选择内存镜像文件。",
                    "tool_events": [{
                        "name": "request_load_image",
                        "arguments": {
                            "os_type": result.get("action", {}).get("os_type", "auto"),
                            "image_path": result.get("action", {}).get("path", ""),
                        },
                        "status": result.get("status"),
                        "summary": result.get("message") or "",
                        "action": result.get("action"),
                    }],
                    "pending_action": result.get("action"),
                    "timestamp": datetime.now().isoformat(),
                },
            }

        symbol_path = _extract_symbol_path(user_message)
        if symbol_path:
            result = self._tool_install_symbols_for_image({
                "os_type": _guess_os_type(user_message),
                "method": "local",
                "symbol_path": symbol_path,
            })
            return {
                "status": "success",
                "data": {
                    "message": result.get("message") or "确认后将校验并安装本地符号表。",
                    "tool_events": [{
                        "name": "install_symbols_for_image",
                        "arguments": {"method": "local", "symbol_path": symbol_path},
                        "status": result.get("status"),
                        "summary": result.get("message") or "",
                        "action": result.get("action"),
                    }],
                    "pending_action": result.get("action"),
                    "timestamp": datetime.now().isoformat(),
                },
            }

        messages = self._build_messages(user_message, history or [])
        tool_events: List[Dict[str, Any]] = []
        logger.info(
            "AI 工具编排开始: history=%d, max_tool_rounds=%d",
            len(history or []),
            self.config.max_tool_rounds,
        )

        try:
            for round_index in range(1, self.config.max_tool_rounds + 1):
                response = self.client.chat(messages, AI_TOOLS, "auto")
                if not response.tool_calls:
                    logger.info(
                        "AI 工具编排完成: round=%d, tool_events=%d",
                        round_index,
                        len(tool_events),
                    )
                    return {
                        "status": "success",
                        "data": {
                            "message": response.content or "没有生成有效回答",
                            "tool_events": tool_events,
                            "timestamp": datetime.now().isoformat(),
                        },
                    }

                tool_names = [
                    str((call.get("function") or {}).get("name") or "unknown")
                    for call in response.tool_calls
                ]
                logger.info(
                    "AI 工具调用: round=%d/%d, names=%s",
                    round_index,
                    self.config.max_tool_rounds,
                    ",".join(tool_names),
                )
                messages.append({
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": response.tool_calls,
                })

                for call in response.tool_calls:
                    name = (call.get("function") or {}).get("name")
                    arguments = self._parse_arguments((call.get("function") or {}).get("arguments"))
                    result = self._run_tool(name, arguments)
                    tool_event = {
                        "name": name,
                        "arguments": self._safe_event_arguments(arguments),
                        "status": result.get("status", "success"),
                        "summary": result.get("message") or result.get("summary") or "",
                        "action": result.get("action"),
                    }
                    compact_result = self._compact_tool_result_for_event(name, result)
                    if compact_result is not None:
                        tool_event["result"] = compact_result
                    tool_events.append(tool_event)
                    if result.get("status") == "requires_confirmation":
                        return {
                            "status": "success",
                            "data": {
                                "message": result.get("message") or "该操作需要确认后执行。",
                                "tool_events": tool_events,
                                "pending_action": result.get("action"),
                                "timestamp": datetime.now().isoformat(),
                            },
                        }
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "name": name,
                        "content": json.dumps(result, ensure_ascii=False),
                    })

            response = self.client.chat(messages, None, "none")
            return {
                "status": "success",
                "data": {
                    "message": response.content or "已达到工具调用轮数上限，请缩小问题范围后重试。",
                    "tool_events": tool_events,
                    "timestamp": datetime.now().isoformat(),
                },
            }
        except AIClientError as exc:
            return {"status": "error", "message": str(exc)}
        except Exception as exc:
            logger.exception("AI 对话失败")
            return {"status": "error", "message": f"AI 对话失败: {exc}"}

    def confirm_action(
        self,
        action: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        try:
            if not isinstance(action, dict):
                return {"status": "error", "message": "确认动作无效"}

            action_type = action.get("type")
            if action_type == "run_plugin":
                result = self._tool_run_plugin({
                    "plugin_id": action.get("plugin_id"),
                    "params": action.get("params") or None,
                    "_confirmed": True,
                })
                tool_name = "run_plugin"
                tool_arguments = {
                    "plugin_id": action.get("plugin_id"),
                    "params": action.get("params") or None,
                }
            elif action_type == "install_symbols":
                result = self._tool_install_symbols_for_image({
                    "os_type": action.get("os_type") or "auto",
                    "method": action.get("method") or "auto",
                    "_confirmed": True,
                })
                tool_name = "install_symbols_for_image"
                tool_arguments = {
                    "os_type": action.get("os_type") or "auto",
                    "method": action.get("method") or "auto",
                }
            elif action_type == "select_symbol_file":
                result = self.api.select_and_install_symbol_for_current_image()
                tool_name = "select_symbol_file"
                tool_arguments = {"os_type": action.get("os_type") or "auto"}
            elif action_type == "install_symbol_path":
                symbol_path = str(action.get("path") or "").strip()
                result = self.api.select_and_install_symbol_for_current_image(symbol_path)
                tool_name = "install_symbol_path"
                tool_arguments = {
                    "os_type": action.get("os_type") or "auto",
                    "symbol_path": symbol_path,
                }
            else:
                return {"status": "error", "message": f"不支持的确认动作: {action_type}"}
            if result.get("status") != "success":
                return result

            if tool_name in ("install_symbols_for_image", "select_symbol_file", "install_symbol_path"):
                return {
                    "status": "success",
                    "data": {
                        "message": result.get("message") or "匹配符号表已安装。",
                        "tool_events": [{
                            "name": tool_name,
                            "arguments": self._safe_event_arguments(tool_arguments),
                            "status": "success",
                            "summary": result.get("message") or "",
                        }],
                        "timestamp": datetime.now().isoformat(),
                    },
                }

            messages = self._build_messages(
                "用户已确认执行工具。请根据下面的工具结果给出简洁取证总结，列出关键发现和下一步建议。",
                history or [],
            )
            messages.append({
                "role": "system",
                "content": f"确认执行结果：{json.dumps(result, ensure_ascii=False)}",
            })
            response = self.client.chat(messages, None, "none")
            return {
                "status": "success",
                "data": {
                    "message": response.content or result.get("message") or "插件执行完成。",
                    "tool_events": [{
                        "name": tool_name,
                        "arguments": self._safe_event_arguments(tool_arguments),
                        "status": "success",
                        "summary": result.get("message") or "",
                    }],
                    "timestamp": datetime.now().isoformat(),
                },
            }
        except AIClientError as exc:
            return {"status": "error", "message": str(exc)}
        except Exception as exc:
            logger.exception("AI 确认动作失败")
            return {"status": "error", "message": f"AI 确认动作失败: {exc}"}

    def _build_messages(self, user_message: str, history: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        context = self._get_context()
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": f"当前工具上下文：{json.dumps(context, ensure_ascii=False)}"},
        ]
        for item in history[-12:]:
            role = item.get("role")
            content = item.get("content")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content[:6000]})
        messages.append({"role": "user", "content": user_message})
        return messages

    def _get_context(self) -> Dict[str, Any]:
        image = self.api.current_image or None
        cached = self.api.get_cached_plugins(False) if image else {"status": "success", "data": {"plugins": []}}
        plugins = []
        for plugin in (cached.get("data") or {}).get("plugins", []):
            plugins.append({
                "pluginId": plugin.get("pluginId"),
                "displayName": plugin.get("displayName"),
                "count": plugin.get("count"),
                "timestamp": plugin.get("timestamp"),
                "isFlagSearch": bool(plugin.get("isFlagSearch")),
            })
        return {
            "image": self._safe_image_info(image),
            "cached_plugins": plugins[:50],
            "cached_plugin_count": len(plugins),
        }

    def _safe_image_info(self, image: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not image:
            return None
        return {
            "name": image.get("name"),
            "hash": image.get("hash"),
            "cache_fingerprint": image.get("cache_fingerprint"),
            "size": image.get("size"),
            "os_type": image.get("os_type"),
            "banner": image.get("banner"),
            "loaded_at": image.get("loaded_at"),
        }

    def _run_tool(self, name: Optional[str], arguments: Dict[str, Any]) -> Dict[str, Any]:
        tools: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "get_current_image": self._tool_get_current_image,
            "get_symbol_status": self._tool_get_symbol_status,
            "install_symbols_for_image": self._tool_install_symbols_for_image,
            "request_load_image": self._tool_request_load_image,
            "list_cached_plugins": self._tool_list_cached_plugins,
            "read_cached_plugin": self._tool_read_cached_plugin,
            "build_analysis_plan": self._tool_build_analysis_plan,
            "build_evidence_index": self._tool_build_evidence_index,
            "build_timeline": self._tool_build_timeline,
            "open_path": self._tool_open_path,
            "reveal_path": self._tool_reveal_path,
            "run_plugin": self._tool_run_plugin,
            "search_flag": self._tool_search_flag,
        }
        if name not in tools:
            return {"status": "error", "message": f"未知工具: {name}"}
        return tools[name](arguments)

    def _tool_get_current_image(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "success", "data": self._safe_image_info(self.api.current_image)}

    def _tool_get_symbol_status(self, _: Dict[str, Any]) -> Dict[str, Any]:
        result = self.api.get_symbol_status()
        if result.get("status") != "success":
            return result
        data = result.get("data") or {}
        current_os = self._normalize_symbol_os(data.get("current_os"))
        os_types = data.get("os_types") or {}
        return {
            "status": "success",
            "message": "已读取当前镜像的符号表状态",
            "data": {
                "current_os": current_os or None,
                "current": os_types.get(current_os) if current_os else None,
            },
        }

    @staticmethod
    def _normalize_symbol_os(value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in ("macos", "darwin"):
            return "mac"
        if normalized in ("windows", "linux", "mac"):
            return normalized
        return ""

    def _tool_install_symbols_for_image(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        image = self.api.current_image or None
        if not image:
            return {"status": "error", "message": "请先加载内存镜像"}

        current_os = self._normalize_symbol_os(image.get("os_type"))
        requested_os = self._normalize_symbol_os(arguments.get("os_type"))
        if not current_os:
            return {"status": "error", "message": "无法识别当前镜像系统类型，不能自动安装符号表"}
        if requested_os and requested_os != current_os:
            return {
                "status": "error",
                "message": f"请求安装 {requested_os} 符号表，但当前镜像是 {current_os}，已拒绝执行",
            }

        method = str(arguments.get("method") or "auto").strip().lower()
        symbol_path = str(arguments.get("symbol_path") or arguments.get("path") or "").strip().strip("\"'`“”‘’")
        if method not in ("auto", "official", "vol", "build", "local"):
            method = "auto"
        if current_os != "windows" and method == "vol":
            return {"status": "error", "message": "vol 下载方式仅适用于 Windows 镜像"}
        if current_os != "linux" and method == "build":
            return {"status": "error", "message": "自动构建方式仅适用于 Linux 镜像"}

        status_result = self._tool_get_symbol_status({})
        current_status = (status_result.get("data") or {}).get("current") or {}
        if current_os == "windows":
            matching_exists = bool((current_status.get("pdb_info") or {}).get("symbol_exists"))
        else:
            matching_exists = bool(current_status.get("kernel_symbol_exists"))
        if matching_exists:
            return {
                "status": "success",
                "message": "当前镜像匹配的符号表已经安装，无需重复下载",
                "data": {"os_type": current_os, "already_exists": True, "symbol_status": current_status},
            }

        if method == "local":
            if symbol_path:
                return {
                    "status": "requires_confirmation",
                    "message": f"已识别本地符号表路径：`{symbol_path}`。确认后会先与当前镜像精确匹配，校验通过才安装。",
                    "action": {
                        "type": "install_symbol_path",
                        "os_type": current_os,
                        "path": symbol_path,
                    },
                }
            return {
                "status": "requires_confirmation",
                "message": f"可以自行选择本地 {current_os} 符号表。选择后会先与当前镜像精确匹配，不匹配的文件不会安装。",
                "action": {"type": "select_symbol_file", "os_type": current_os},
            }

        if not arguments.get("_confirmed"):
            auto_method_text = (
                "使用 LensAnalysis 当前解析到的 vol 命令下载"
                if current_os == "windows"
                else "自动选择现有下载链路"
            )
            method_text = {
                "auto": auto_method_text,
                "official": "使用现有官方下载链路",
                "vol": "使用 vol 命令下载",
                "build": "下载调试包并自动构建",
            }[method]
            return {
                "status": "requires_confirmation",
                "message": f"当前 {current_os} 镜像没有检测到匹配符号表。确认后将{method_text}，过程可能需要数分钟并使用网络。",
                "action": {
                    "type": "install_symbols",
                    "os_type": current_os,
                    "method": method,
                    "alternative_action": {
                        "type": "select_symbol_file",
                        "os_type": current_os,
                    },
                },
            }

        if current_os == "windows":
            result = (
                self.api.download_windows_symbols_via_vol()
                if method in ("auto", "vol")
                else self.api.download_windows_symbols()
            )
        elif current_os == "linux" and method == "build":
            result = self.api.build_linux_symbol_table()
        else:
            result = self.api.download_symbols_from_github(current_os)

        if result.get("status") == "success":
            verification = self._tool_get_symbol_status({})
            result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
            result_data["verification"] = (verification.get("data") or {}).get("current")
            result["data"] = result_data
        return result

    def _compact_tool_result_for_event(self, name: Optional[str], result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if result.get("status") != "success":
            return None
        data = result.get("data")
        if name == "build_evidence_index" and isinstance(data, dict):
            return {
                "evidence": (data.get("evidence") or [])[:10],
                "evidence_count": data.get("evidence_count", 0),
                "total_candidates": data.get("total_candidates", 0),
            }
        return None

    def _tool_request_load_image(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        os_type = str(arguments.get("os_type") or "auto").strip()
        image_path = str(arguments.get("image_path") or arguments.get("path") or "").strip().strip("\"'`“”‘’")
        if os_type.lower() in ("", "auto", "unknown", "自动", "自动检测"):
            os_type = "auto"
        allowed = {"auto", "Windows", "Linux", "macOS", "mac"}
        normalized = {
            "windows": "Windows",
            "linux": "Linux",
            "mac": "macOS",
            "macos": "macOS",
        }.get(os_type.lower(), os_type)
        if normalized not in allowed:
            normalized = "auto"
        if image_path:
            return {
                "status": "requires_confirmation",
                "message": f"我识别到镜像路径：`{image_path}`。确认后会直接加载这个文件。",
                "action": {
                    "type": "load_image_path",
                    "path": image_path,
                    "os_type": normalized,
                },
            }
        return {
            "status": "requires_confirmation",
            "message": "可以，我需要打开系统文件选择器来加载内存镜像。确认后请选择 .raw、.mem、.vmem、.dmp 或 .lime 等镜像文件。",
            "action": {
                "type": "load_image_dialog",
                "os_type": normalized,
            },
        }

    def _tool_list_cached_plugins(self, _: Dict[str, Any]) -> Dict[str, Any]:
        result = self.api.get_cached_plugins(False)
        if result.get("status") != "success":
            return result
        plugins = []
        for plugin in (result.get("data") or {}).get("plugins", []):
            plugins.append({
                "pluginId": plugin.get("pluginId"),
                "displayName": plugin.get("displayName"),
                "count": plugin.get("count"),
                "timestamp": plugin.get("timestamp"),
                "isFlagSearch": bool(plugin.get("isFlagSearch")),
            })
        return {"status": "success", "data": {"plugins": plugins, "count": len(plugins)}}

    def _tool_read_cached_plugin(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api.current_image:
            return {"status": "error", "message": "请先加载内存镜像"}

        plugin_id = str(arguments.get("plugin_id") or "").strip()
        if not plugin_id:
            return {"status": "error", "message": "缺少 plugin_id"}

        limit = _clamp_int(arguments.get("limit"), 1, 200, 50)
        offset = _clamp_int(arguments.get("offset"), 0, 1_000_000, 0)
        keyword = str(arguments.get("keyword") or "").strip().lower()

        if plugin_id.startswith("flag_search_"):
            return self._read_flag_cache(plugin_id, limit, offset)

        cache_key = self.api._get_cache_key(plugin_id, arguments.get("params") or None)
        data = self.api._load_from_cache_file(cache_key)
        if not data:
            return {"status": "error", "message": f"没有找到 {plugin_id} 的缓存，请先执行该插件"}

        rows = data.get("results") or []
        if keyword:
            rows = [
                row for row in rows
                if self.api._row_contains_keyword(row, keyword)
            ]

        page = rows[offset:offset + limit]
        return {
            "status": "success",
            "data": {
                "plugin_id": plugin_id,
                "total": len(rows),
                "offset": offset,
                "limit": limit,
                "rows": page,
                "truncated": offset + limit < len(rows),
            },
        }

    def _tool_build_analysis_plan(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return self.api.ai_generate_analysis_plan()

    def _tool_build_evidence_index(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        limit = _clamp_int(arguments.get("limit"), 3, 50, 12)
        return self.api.ai_build_evidence_index(limit)

    def _tool_build_timeline(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        limit = _clamp_int(arguments.get("limit"), 10, 300, 80)
        return self.api.ai_build_timeline(limit)

    def _tool_open_path(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        path = str(arguments.get("path") or "").strip().strip("\"'`“”‘’")
        if not path:
            return {"status": "error", "message": "缺少 path"}
        return self.api.open_path(path)

    def _tool_reveal_path(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        path = str(arguments.get("path") or "").strip().strip("\"'`“”‘’")
        if not path:
            return {"status": "error", "message": "缺少 path"}
        return self.api.reveal_path(path)

    def _tool_run_plugin(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api.current_image:
            return {"status": "error", "message": "请先加载内存镜像"}

        plugin_id = str(arguments.get("plugin_id") or "").strip()
        if not plugin_id:
            return {"status": "error", "message": "缺少 plugin_id"}
        requested_plugin_id = plugin_id
        if hasattr(self.api, "normalize_plugin_id"):
            plugin_id = self.api.normalize_plugin_id(plugin_id)

        params = arguments.get("params") or None
        display_name = self.api._get_plugin_display_name(plugin_id)
        full_name = self.api.get_plugin_full_name(plugin_id) if hasattr(self.api, "get_plugin_full_name") else ""
        execution_label = full_name or plugin_id
        if not self.allow_plugin_execution and not arguments.get("_confirmed"):
            return {
                "status": "requires_confirmation",
                "message": f"AI 建议执行 {display_name}（{execution_label}）。确认后会通过 LensAnalysis 原有链路运行。",
                "action": {
                    "type": "run_plugin",
                    "plugin_id": plugin_id,
                    "requested_plugin_id": requested_plugin_id,
                    "display_name": display_name,
                    "plugin_full_name": full_name,
                    "params": params,
                },
            }

        operation_result = self._run_api_operation(plugin_id, params or {})
        if operation_result is not None:
            return operation_result

        result = self.api.run_analysis(plugin_id, params)
        if result.get("status") != "success":
            return result

        data = result.get("data") or {}
        rows = data.get("results") or []
        return {
            "status": "success",
            "message": f"{display_name}（{execution_label}）执行完成，共 {len(rows)} 条记录",
            "data": {
                "plugin_id": plugin_id,
                "plugin_full_name": full_name,
                "count": len(rows),
                "cached": result.get("cached", False),
                "sample": rows[:30],
            },
        }

    def _run_api_operation(self, operation: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        output_dir = params.get("output_dir") or params.get("outputDir")
        default_extract_dir = self.api._default_export_dir("files")
        default_dump_dir = self.api._default_export_dir("processes")

        try:
            if operation == "dump_process_memory":
                pid = params.get("pid") or params.get("PID") or params.get("process_id")
                if pid in (None, ""):
                    return {"status": "error", "message": "dump_process_memory 缺少 pid 参数"}
                result = self.api.dump_process_memory(
                    int(pid),
                    output_dir or default_dump_dir,
                    params.get("source_plugin") or params.get("plugin_id"),
                )
            elif operation in ("extract_file", "dump_file"):
                offset = (
                    params.get("offset")
                    or params.get("Offset")
                    or params.get("virtual_offset")
                    or params.get("physical_offset")
                )
                if not offset:
                    return {"status": "error", "message": f"{operation} 缺少 offset 参数"}
                requested_name = (
                    params.get("file_name")
                    or params.get("name")
                    or params.get("path")
                )
                result = self.api.dump_file(
                    str(offset),
                    output_dir or default_extract_dir,
                    requested_name,
                )
            elif operation == "dump_files":
                result = self.api.dump_files(
                    params.get("filter_pattern") or params.get("pattern"),
                    bool(params.get("ignore_case", False)),
                    params.get("pid"),
                    output_dir or self.api._default_export_dir("linux_filesystem"),
                )
            elif operation == "extract_pagecache_file":
                file_path = params.get("file_path") or params.get("path")
                if not file_path:
                    return {"status": "error", "message": "extract_pagecache_file 缺少 file_path 参数"}
                result = self.api.extract_pagecache_file(str(file_path), output_dir or default_extract_dir)
            elif operation == "extract_dll":
                pid = params.get("pid")
                base = params.get("base")
                if pid in (None, "") or not base:
                    return {"status": "error", "message": "extract_dll 缺少 pid 或 base 参数"}
                result = self.api.extract_dll(str(pid), str(base), output_dir or default_extract_dir)
            elif operation == "extract_elf_file":
                pid = params.get("pid")
                start = params.get("start")
                if pid in (None, "") or not start:
                    return {"status": "error", "message": "extract_elf_file 缺少 pid 或 start 参数"}
                result = self.api.extract_elf_file(str(pid), str(start), params.get("file_name") or "extracted.elf", output_dir or default_extract_dir)
            elif operation == "extract_lsof_file":
                file_path = params.get("file_path") or params.get("path")
                plugin_id = params.get("source_plugin") or params.get("plugin_id") or "linux_lsof"
                if not file_path:
                    return {"status": "error", "message": "extract_lsof_file 缺少 file_path 参数"}
                result = self.api.extract_lsof_file(str(file_path), str(plugin_id), output_dir or default_extract_dir)
            elif operation == "extract_lsof_files":
                result = self.api.extract_lsof_files(str(params.get("source_plugin") or params.get("plugin_id") or "linux_lsof"), output_dir or default_extract_dir)
            elif operation == "extract_elf_files":
                result = self.api.extract_elf_files(params.get("pid"), output_dir or default_extract_dir)
            elif operation == "wechat_decrypt_databases":
                result = self.api.wechat_decrypt_databases()
            elif operation == "wechat_export_keys":
                result = self.api.wechat_export_keys()
            elif operation == "generate_report":
                result = self.api.generate_report(params.get("format") or "markdown")
            elif operation == "ai_generate_report":
                result = self.api.ai_generate_report(params.get("format") or "markdown")
            elif operation == "export_results":
                data = params.get("data") or []
                if not isinstance(data, list):
                    return {"status": "error", "message": "export_results 的 data 参数必须是数组"}
                result = self.api.export_results(data, params.get("format") or params.get("format_type") or "csv")
            else:
                return None

            if result.get("status") != "success":
                return result
            return {
                "status": "success",
                "message": self._format_operation_message(operation, result),
                "data": {
                    "operation": operation,
                    "params": params,
                    "result": result.get("data", result),
                    "paths": self._extract_result_paths(result),
                },
            }
        except Exception as exc:
            logger.exception("AI API 操作执行失败: %s", operation)
            return {"status": "error", "message": f"{operation} 执行失败: {exc}"}

    def _extract_result_paths(self, result: Dict[str, Any]) -> List[str]:
        paths: List[str] = []

        def is_likely_host_path(value: Any) -> bool:
            text = str(value or "").strip()
            if not text or text in ("-", "/") or len(text) < 3:
                return False
            if re.match(r"^[A-Za-z]:[\\/][^<>:\"|?*\r\n]+", text):
                return True
            if re.match(r"^~/[^`\"'<>，。！？；;、\r\n]+", text):
                return True
            return bool(re.match(
                r"^/(?:Users|Volumes|Applications|tmp|private|var|home|opt|usr|etc|Library|System|bin|sbin|mnt|media|root)(?:/|$)",
                text,
            ))

        def add(value: Any) -> None:
            if not value:
                return
            text = str(value).strip()
            if is_likely_host_path(text) and text not in paths:
                paths.append(text)

        def walk(value: Any, path_context: bool = False) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    is_path_field = bool(re.search(r"(path|dir|directory|output|export|report|file)", str(key), re.I))
                    walk(item, path_context or is_path_field)
            elif isinstance(value, list):
                for item in value:
                    walk(item, path_context)
            elif isinstance(value, str):
                if path_context:
                    add(value)

        walk(result)
        return paths[:10]

    def _format_operation_message(self, operation: str, result: Dict[str, Any]) -> str:
        paths = self._extract_result_paths(result)
        base = result.get("message") or f"{operation} 执行完成"
        if paths:
            return f"{base}\n\n主要路径：`{paths[0]}`"
        return base

    def _tool_search_flag(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        patterns = arguments.get("patterns")
        if patterns is not None and not isinstance(patterns, list):
            return {"status": "error", "message": "patterns 必须是字符串数组"}
        result = self.api.search_flag(patterns=patterns, force=False)
        if result.get("status") != "success":
            return result
        data = result.get("data") or {}
        flags = data.get("flags") or []
        return {
            "status": "success",
            "data": {
                "count": data.get("count", len(flags)),
                "cached": data.get("cached", False),
                "flags": flags[:50],
                "truncated": len(flags) > 50,
            },
        }

    def _read_flag_cache(self, plugin_id: str, limit: int, offset: int) -> Dict[str, Any]:
        self.api._load_flag_search_cache_from_file()
        cache = getattr(self.api, "_flag_search_cache", {})
        key = "default" if plugin_id == "flag_search_default" else ""
        if plugin_id.startswith("flag_search_custom:"):
            key = f"custom:{plugin_id.split(':', 1)[1]}"
        entry = cache.get(key) if cache else None
        if not entry:
            return {"status": "error", "message": f"没有找到 {plugin_id} 的 Flag 搜索缓存"}
        rows = entry.get("results") or []
        return {
            "status": "success",
            "data": {
                "plugin_id": plugin_id,
                "total": len(rows),
                "rows": rows[offset:offset + limit],
                "truncated": offset + limit < len(rows),
            },
        }

    def _parse_arguments(self, value: Any) -> Dict[str, Any]:
        if not value:
            return {}
        if isinstance(value, dict):
            return value
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _safe_event_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return dict(arguments)


AI_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_current_image",
            "description": "获取当前已加载内存镜像的基本信息。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_symbol_status",
            "description": "检查当前镜像是否已经安装完全匹配的 Volatility 符号表。插件提示缺少、无法加载或符号不匹配时应先调用此工具。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "install_symbols_for_image",
            "description": "为当前内存镜像安装匹配符号表。该操作使用网络且必须由用户确认。Windows 默认使用 LensAnalysis 当前解析到的 vol 命令下载（优先自定义 vol，否则使用对应 Python 环境的 vol）；只有用户明确要求其他官方下载链路时 method 传 official。Linux 默认下载预编译表，用户明确要求自动制作时传 build；macOS 使用现有下载链路。",
            "parameters": {
                "type": "object",
                "properties": {
                    "os_type": {
                        "type": "string",
                        "enum": ["auto", "windows", "linux", "mac"],
                        "description": "通常使用 auto；仅在用户明确指定时填写系统类型。",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["auto", "official", "vol", "build", "local"],
                        "description": "安装方式。通常使用 auto；vol 仅限 Windows，build 仅限 Linux；用户要求自行选择本地文件时使用 local。",
                    },
                    "symbol_path": {
                        "type": "string",
                        "description": "用户在对话中明确给出的本地 .zip、.json 或 .json.xz 符号表路径；未给出路径时留空。",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_load_image",
            "description": "当用户要求加载、打开、选择或切换内存镜像时调用。用户给出本地路径时传 image_path；否则前端会在用户确认后打开系统文件选择器。",
            "parameters": {
                "type": "object",
                "properties": {
                    "os_type": {
                        "type": "string",
                        "enum": ["auto", "Windows", "Linux", "macOS"],
                        "description": "用户明确指定的镜像系统类型；未指定时使用 auto。",
                    },
                    "image_path": {
                        "type": "string",
                        "description": "用户消息中给出的本地内存镜像路径，例如 /Users/me/image.raw 或 C:\\\\Users\\\\me\\\\image.mem；没有路径时留空。",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_cached_plugins",
            "description": "列出当前镜像已经缓存的分析结果。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_cached_plugin",
            "description": "分页读取某个插件的本地 JSON 缓存结果。",
            "parameters": {
                "type": "object",
                "properties": {
                    "plugin_id": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "offset": {"type": "integer", "minimum": 0},
                    "keyword": {"type": "string"},
                    "params": {"type": "object"},
                },
                "required": ["plugin_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_analysis_plan",
            "description": "根据当前镜像系统类型和已有缓存生成分阶段取证分析计划，包含推荐插件、是否已有缓存和执行原因。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_evidence_index",
            "description": "从当前镜像本地插件缓存中提取带来源定位的线索索引，用于回答时引用具体插件、缓存文件和记录序号。",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 3, "maximum": 50},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_timeline",
            "description": "从当前镜像本地插件缓存中提取时间字段并生成案件时间线，用于按时间还原进程、网络、文件、注册表、用户活动等事件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 10, "maximum": 300},
                },
            },
        },
    },
    {
        "type": "function",
            "function": {
                "name": "run_plugin",
            "description": "通过 LensAnalysis 原有链路运行 Volatility 插件或取证操作。普通插件传插件 ID；导出/解密/dump 可传操作名，例如 dump_process_memory、dump_file、dump_files、extract_file、extract_dll、extract_elf_file、extract_pagecache_file、wechat_decrypt_databases、wechat_export_keys、generate_report、ai_generate_report、export_results。",
            "parameters": {
                "type": "object",
                "properties": {
                    "plugin_id": {
                        "type": "string",
                        "description": "插件 ID 或操作名。操作名示例：dump_process_memory、dump_file、dump_files、extract_file、wechat_decrypt_databases、generate_report。",
                    },
                    "params": {
                        "type": "object",
                        "description": "插件参数或操作参数，例如 {\"pid\": 1234}、{\"offset\": \"0x1234\", \"output_dir\": \"/tmp/out\"}、{\"format\": \"markdown\"}。",
                    },
                },
                "required": ["plugin_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "open_path",
            "description": "打开本机文件或文件夹。适用于用户要求打开报告、打开导出文件、打开目录等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "本机文件或文件夹路径"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reveal_path",
            "description": "在 Finder、Explorer 或文件管理器中定位指定文件或文件夹。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "需要定位的本机文件或文件夹路径"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_flag",
            "description": "搜索内存中的 CTF Flag，可传自定义正则数组。",
            "parameters": {
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
    },
]


def _clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _guess_os_type(text: str) -> str:
    lowered = (text or "").lower()
    if "windows" in lowered or "win" in lowered:
        return "Windows"
    if "linux" in lowered:
        return "Linux"
    if "macos" in lowered or "mac os" in lowered or "darwin" in lowered or "苹果" in lowered:
        return "macOS"
    return "auto"


def _extract_image_path(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    extensions = r"(?:raw|mem|vmem|dmp|lime|img|bin|aff4)"
    quoted = re.search(
        rf"[\"'`“”‘’]((?:~|/|[A-Za-z]:[\\/])[^\"'`“”‘’\r\n]+?\.{extensions})[\"'`“”‘’]",
        text,
        re.IGNORECASE,
    )
    if quoted:
        return quoted.group(1).strip()

    unquoted = re.search(
        rf"((?:~|/|[A-Za-z]:[\\/])[\S ]+?\.{extensions})(?=$|[\s，。！？；;、,])",
        text,
        re.IGNORECASE,
    )
    if unquoted:
        return unquoted.group(1).strip()
    return ""


def _extract_symbol_path(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    extensions = r"(?:json\.xz|json|zip)"
    quoted = re.search(
        rf"[\"'`“”‘’]((?:~|/|[A-Za-z]:[\\/])[^\"'`“”‘’\r\n]+?\.{extensions})[\"'`“”‘’]",
        text,
        re.IGNORECASE,
    )
    if quoted:
        return quoted.group(1).strip()
    unquoted = re.search(
        rf"((?:~|/|[A-Za-z]:[\\/])[\S ]+?\.{extensions})(?=$|[\s，。！？；;、,])",
        text,
        re.IGNORECASE,
    )
    return unquoted.group(1).strip() if unquoted else ""
