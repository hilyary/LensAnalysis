from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .config import AIConfig

logger = logging.getLogger(__name__)


@dataclass
class AIModelResponse:
    content: str
    tool_calls: List[Dict[str, Any]]
    raw: Dict[str, Any]


class AIClientError(RuntimeError):
    pass


class OpenAICompatibleClient:

    _sdk_clients: "OrderedDict[str, Any]" = OrderedDict()
    _sdk_clients_lock = threading.RLock()
    _max_cached_sdk_clients = 8

    def __init__(self, config: AIConfig, proxy_url: Optional[str] = None):
        self.config = config
        self.proxy_url = proxy_url

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
    ) -> AIModelResponse:
        if not self.config.enabled:
            raise AIClientError("AI 功能未启用，请先在设置中开启")

        ok, message = self.config.validate()
        if not ok:
            raise AIClientError(message)

        started_at = time.monotonic()
        message_chars = self._estimate_message_chars(messages)
        logger.info(
            "AI 请求开始: provider=%s, model=%s, messages=%d, "
            "message_chars=%d, tools=%d, tool_choice=%s",
            self.config.provider,
            self.config.model,
            len(messages),
            message_chars,
            len(tools or []),
            tool_choice,
        )

        transport = "openai_sdk"
        try:
            try:
                response = self._chat_with_openai_sdk(messages, tools, tool_choice)
            except ImportError:
                transport = "requests"
                logger.info("openai SDK 未安装，使用 requests 兼容模式")
                response = self._chat_with_requests(messages, tools, tool_choice)
            except Exception as exc:
                transport = "requests_fallback"
                logger.warning("openai SDK 调用失败，尝试 requests 兼容模式: %s", exc)
                response = self._chat_with_requests(messages, tools, tool_choice)

            elapsed = time.monotonic() - started_at
            usage = response.raw.get("usage") if isinstance(response.raw, dict) else {}
            usage = usage if isinstance(usage, dict) else {}
            logger.info(
                "AI 请求完成: provider=%s, model=%s, transport=%s, "
                "elapsed=%.2fs, prompt_tokens=%s, completion_tokens=%s, tool_calls=%d",
                self.config.provider,
                self.config.model,
                transport,
                elapsed,
                usage.get("prompt_tokens", "-"),
                usage.get("completion_tokens", "-"),
                len(response.tool_calls),
            )
            return response
        except Exception:
            logger.warning(
                "AI 请求失败: provider=%s, model=%s, transport=%s, elapsed=%.2fs",
                self.config.provider,
                self.config.model,
                transport,
                time.monotonic() - started_at,
            )
            raise

    @staticmethod
    def _estimate_message_chars(messages: List[Dict[str, Any]]) -> int:
        total = 0
        for message in messages:
            total += len(str(message.get("content") or ""))
            for key in ("tool_calls", "function_call"):
                value = message.get(key)
                if value:
                    try:
                        total += len(json.dumps(value, ensure_ascii=False))
                    except (TypeError, ValueError):
                        total += len(str(value))
        return total

    def _sdk_client_cache_key(self) -> str:
        key_material = "\0".join((
            self.config.base_url.rstrip("/"),
            self.config.api_key or "local",
            self.proxy_url or "",
            str(self.config.timeout),
        ))
        return hashlib.sha256(key_material.encode("utf-8")).hexdigest()

    def _get_openai_sdk_client(self) -> Any:
        from openai import OpenAI

        cache_key = self._sdk_client_cache_key()
        with self._sdk_clients_lock:
            cached = self._sdk_clients.get(cache_key)
            if cached is not None:
                self._sdk_clients.move_to_end(cache_key)
                return cached

            kwargs: Dict[str, Any] = {
                "api_key": self.config.api_key or "local",
                "base_url": self.config.base_url,
                "timeout": self.config.timeout,
            }
            if self.proxy_url:
                import httpx

                kwargs["http_client"] = httpx.Client(
                    proxy=self.proxy_url,
                    timeout=self.config.timeout,
                )

            client = OpenAI(**kwargs)
            self._sdk_clients[cache_key] = client
            while len(self._sdk_clients) > self._max_cached_sdk_clients:
                _, old_client = self._sdk_clients.popitem(last=False)
                try:
                    old_client.close()
                except Exception:
                    logger.debug("关闭旧 OpenAI SDK 客户端失败", exc_info=True)
            return client

    @classmethod
    def close_cached_sdk_clients(cls) -> None:
        with cls._sdk_clients_lock:
            clients = list(cls._sdk_clients.values())
            cls._sdk_clients.clear()
        for client in clients:
            try:
                client.close()
            except Exception:
                logger.debug("关闭 OpenAI SDK 客户端失败", exc_info=True)

    def _chat_with_openai_sdk(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]],
        tool_choice: str,
    ) -> AIModelResponse:
        client = self._get_openai_sdk_client()
        request: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
        }
        if tools:
            request["tools"] = tools
            request["tool_choice"] = tool_choice

        response = client.chat.completions.create(**request)
        choice = response.choices[0].message
        tool_calls = []
        for call in choice.tool_calls or []:
            tool_calls.append({
                "id": call.id,
                "type": call.type,
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments or "{}",
                },
            })
        return AIModelResponse(
            content=choice.content or "",
            tool_calls=tool_calls,
            raw=response.model_dump() if hasattr(response, "model_dump") else {},
        )

    def _chat_with_requests(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]],
        tool_choice: str,
    ) -> AIModelResponse:
        endpoint = f"{self.config.base_url.rstrip('/')}/chat/completions"
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        proxies = None
        if self.proxy_url:
            proxies = {"http": self.proxy_url, "https": self.proxy_url}

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=self.config.timeout,
                proxies=proxies,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise AIClientError(f"模型接口请求失败: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AIClientError("模型接口返回了非 JSON 响应") from exc

        choices = data.get("choices") or []
        if not choices:
            raise AIClientError("模型接口未返回有效回答")
        message = choices[0].get("message") or {}
        return AIModelResponse(
            content=message.get("content") or "",
            tool_calls=message.get("tool_calls") or [],
            raw=data,
        )
