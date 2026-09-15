from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


def _model(model_id: str, label: str | None = None, badge: str | None = None, description: str | None = None) -> Dict[str, str]:
    item = {"id": model_id, "name": label or model_id}
    if badge:
        item["badge"] = badge
    if description:
        item["description"] = description
    return item


def _cc_provider(
    provider_id: str,
    name: str,
    base_url: str,
    default_model: str,
    *,
    category: str = "aggregator",
    badge: str = "预设",
    website_url: str = "",
    api_key_url: str = "",
    endpoint_candidates: List[str] | None = None,
    models: List[Dict[str, str]] | None = None,
    api_format: str = "openai_chat",
    description: str = "",
) -> Dict[str, Any]:
    endpoints = endpoint_candidates or [base_url]
    return {
        "id": provider_id,
        "name": name,
        "category": category,
        "badge": badge,
        "base_url": base_url,
        "endpoint_candidates": endpoints,
        "models_url": f"{base_url.rstrip('/')}/models",
        "models": models or [_model(default_model, default_model, "默认")],
        "default_model": default_model,
        "website_url": website_url,
        "api_key_url": api_key_url or website_url,
        "description": description or f"参考 cc-switch 供应商预设整理，默认模型：{default_model}。",
        "requires_key": True,
        "api_format": api_format,
        "source": "cc-switch",
    }


AI_PROVIDER_PRESETS: List[Dict[str, Any]] = [
    {
        "id": "openai",
        "name": "OpenAI",
        "category": "official",
        "badge": "官方",
        "base_url": "https://api.openai.com/v1",
        "endpoint_candidates": ["https://api.openai.com/v1"],
        "models": [
            _model("gpt-5.5", "GPT-5.5", "最新", "复杂推理、代码和专业分析，成本最高。"),
            _model("gpt-5.4", "GPT-5.4", "旗舰", "较新的通用旗舰模型，适合高质量分析。"),
            _model("gpt-5.4-mini", "GPT-5.4 mini", "推荐", "兼顾质量、速度和成本，适合小析默认分析。"),
            _model("gpt-5.4-nano", "GPT-5.4 nano", "快速", "低延迟低成本任务。"),
            _model("gpt-4.1-mini", "GPT-4.1 mini", "兼容", "旧项目和 OpenAI-compatible 网关常见稳定选择。"),
        ],
        "default_model": "gpt-5.4-mini",
        "website_url": "https://platform.openai.com",
        "api_key_url": "https://platform.openai.com/api-keys",
        "description": "OpenAI 官方接口，已内置 GPT-5.5 / GPT-5.4 系列和兼容备用模型。",
        "requires_key": True,
    },
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://api.deepseek.com",
        "endpoint_candidates": ["https://api.deepseek.com", "https://api.deepseek.com/v1"],
        "models": [
            _model("deepseek-v4-flash", "DeepSeek V4 Flash", "推荐", "官方 V4 轻量高速版，适合常规取证分析。"),
            _model("deepseek-v4-pro", "DeepSeek V4 Pro", "强推理", "官方 V4 Pro，适合复杂推理和长上下文。"),
            _model("deepseek-chat", "deepseek-chat", "旧兼容", "兼容别名，官方标注将于 2026-07-24 15:59 UTC 弃用。"),
            _model("deepseek-reasoner", "deepseek-reasoner", "旧兼容", "兼容别名，官方标注将于 2026-07-24 15:59 UTC 弃用。"),
        ],
        "default_model": "deepseek-v4-flash",
        "website_url": "https://platform.deepseek.com",
        "api_key_url": "https://platform.deepseek.com/api_keys",
        "description": "DeepSeek 官方兼容接口，已更新到 V4 Flash / V4 Pro。",
        "requires_key": True,
    },
    {
        "id": "dashscope",
        "name": "阿里云百炼 Bailian",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "endpoint_candidates": ["https://dashscope.aliyuncs.com/compatible-mode/v1"],
        "models": [
            _model("qwen3.6-plus", "Qwen3.6 Plus", "新"),
            _model("qwen3.5-plus", "Qwen3.5 Plus", "新"),
            _model("qwen3-coder-plus", "Qwen3 Coder Plus", "代码"),
            _model("qwen-plus-latest", "Qwen Plus Latest", "推荐"),
            _model("qwen-max-latest", "Qwen Max Latest", "高质量"),
            _model("qwen-turbo-latest", "Qwen Turbo Latest", "快速"),
        ],
        "default_model": "qwen-plus-latest",
        "website_url": "https://bailian.console.aliyun.com",
        "api_key_url": "https://bailian.console.aliyun.com/#/api-key",
        "description": "阿里云百炼兼容模式，Qwen 系列模型入口。",
        "requires_key": True,
    },
    {
        "id": "kimi",
        "name": "Kimi / Moonshot",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://api.moonshot.cn/v1",
        "endpoint_candidates": ["https://api.moonshot.cn/v1"],
        "models": [
            _model("kimi-k2.6", "Kimi K2.6", "新"),
            _model("kimi-k2.6-code", "Kimi K2.6 Code", "代码"),
            _model("kimi-k2-thinking", "Kimi K2 Thinking", "推理"),
            _model("kimi-k2.7-code", "Kimi K2.7 Code", "候选"),
            _model("moonshot-v1-128k", "moonshot-v1-128k", "长上下文"),
        ],
        "default_model": "kimi-k2.6",
        "website_url": "https://platform.kimi.com",
        "api_key_url": "https://platform.kimi.com/console/api-keys",
        "description": "Moonshot/Kimi 兼容接口，长上下文与代码模型入口。",
        "requires_key": True,
    },
    {
        "id": "zhipu",
        "name": "智谱 GLM",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "endpoint_candidates": [
            "https://open.bigmodel.cn/api/paas/v4",
            "https://open.bigmodel.cn/api/coding/paas/v4",
        ],
        "models": [
            _model("glm-5.2", "GLM-5.2", "新"),
            _model("glm-5.1", "GLM-5.1", "推荐"),
            _model("glm-4.5", "GLM-4.5", "稳定"),
            _model("glm-4-air", "GLM-4 Air", "快速"),
            _model("glm-4-flash", "GLM-4 Flash", "低成本"),
        ],
        "default_model": "glm-5.1",
        "website_url": "https://open.bigmodel.cn",
        "api_key_url": "https://open.bigmodel.cn/usercenter/proj-mgmt/apikeys",
        "description": "智谱 GLM 官方兼容接口，支持通用对话与推理。",
        "requires_key": True,
    },
    {
        "id": "siliconflow",
        "name": "硅基流动 SiliconFlow",
        "category": "aggregator",
        "badge": "聚合",
        "base_url": "https://api.siliconflow.cn/v1",
        "endpoint_candidates": ["https://api.siliconflow.cn/v1"],
        "models": [
            _model("deepseek-ai/DeepSeek-V4-Flash", "DeepSeek V4 Flash", "新"),
            _model("deepseek-ai/DeepSeek-V4-Pro", "DeepSeek V4 Pro", "强推理"),
            _model("Qwen/Qwen3-Coder-480B-A35B-Instruct", "Qwen3 Coder 480B", "代码"),
            _model("Qwen/Qwen3.6-35B-A3B-Instruct", "Qwen3.6 35B A3B", "新"),
            _model("THUDM/GLM-5.1", "GLM-5.1", "推理"),
            _model("deepseek-ai/DeepSeek-R1", "DeepSeek R1", "经典"),
        ],
        "default_model": "deepseek-ai/DeepSeek-V4-Flash",
        "website_url": "https://cloud.siliconflow.cn",
        "api_key_url": "https://cloud.siliconflow.cn/account/ak",
        "description": "国内常用模型聚合平台，模型丰富，适合第三方 API 接入。",
        "requires_key": True,
    },
    {
        "id": "volcengine",
        "name": "火山方舟 Ark",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "endpoint_candidates": [
            "https://ark.cn-beijing.volces.com/api/v3",
            "https://ark.cn-beijing.volces.com/api/coding/v3",
        ],
        "models": [
            _model("doubao-seed-2-1-pro-260628", "豆包 Seed 2.1 Pro", "推荐"),
            _model("doubao-seed-2-1-flash-260628", "豆包 Seed 2.1 Flash", "快速"),
            _model("ark-code-latest", "Ark Code Latest", "代码"),
        ],
        "default_model": "doubao-seed-2-1-pro-260628",
        "website_url": "https://www.volcengine.com/product/ark",
        "api_key_url": "https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey",
        "description": "火山方舟 OpenAI-compatible 入口，可接豆包/Ark Code 等模型。",
        "requires_key": True,
    },
    {
        "id": "modelscope",
        "name": "ModelScope 魔搭",
        "category": "aggregator",
        "badge": "聚合",
        "base_url": "https://api-inference.modelscope.cn/v1",
        "endpoint_candidates": ["https://api-inference.modelscope.cn/v1"],
        "models": [
            _model("ZhipuAI/GLM-5.1", "GLM-5.1", "推荐"),
            _model("deepseek-ai/DeepSeek-V4-Flash", "DeepSeek V4 Flash", "新"),
            _model("Qwen/Qwen3-Coder-480B-A35B-Instruct", "Qwen3 Coder 480B", "代码"),
            _model("Qwen/Qwen3.6-35B-A3B-Instruct", "Qwen3.6 35B A3B", "新"),
        ],
        "default_model": "ZhipuAI/GLM-5.1",
        "website_url": "https://modelscope.cn",
        "api_key_url": "https://modelscope.cn/my/myaccesstoken",
        "description": "ModelScope 推理 API，适合国内开源模型接入。",
        "requires_key": True,
    },
    {
        "id": "minimax",
        "name": "MiniMax",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://api.minimaxi.com/v1",
        "endpoint_candidates": ["https://api.minimaxi.com/v1", "https://api.minimax.io/v1"],
        "models": [_model("MiniMax-M3", "MiniMax-M3", "推荐")],
        "default_model": "MiniMax-M3",
        "website_url": "https://platform.minimaxi.com",
        "api_key_url": "https://platform.minimaxi.com/user-center/basic-information/interface-key",
        "description": "MiniMax 官方接口，M3 模型适合长上下文任务。",
        "requires_key": True,
    },
    {
        "id": "stepfun",
        "name": "阶跃星辰 StepFun",
        "category": "cn_official",
        "badge": "官方",
        "base_url": "https://api.stepfun.com/v1",
        "endpoint_candidates": ["https://api.stepfun.com/v1", "https://api.stepfun.com/step_plan/v1"],
        "models": [
            _model("step-3.7-flash", "Step 3.7 Flash", "推荐"),
            _model("step-3.5-flash-2603", "Step 3.5 Flash 2603", "稳定"),
            _model("step-3.5-flash", "Step 3.5 Flash", "兼容"),
        ],
        "default_model": "step-3.7-flash",
        "website_url": "https://platform.stepfun.com",
        "api_key_url": "https://platform.stepfun.com/interface-key",
        "description": "StepFun 官方接口，提供 Step 系列模型。",
        "requires_key": True,
    },
    {
        "id": "openrouter",
        "name": "OpenRouter",
        "category": "aggregator",
        "badge": "聚合",
        "base_url": "https://openrouter.ai/api/v1",
        "endpoint_candidates": ["https://openrouter.ai/api/v1"],
        "models": [
            _model("openai/gpt-5.5", "OpenAI GPT-5.5", "最新"),
            _model("openai/gpt-5.4-mini", "OpenAI GPT-5.4 mini", "推荐"),
            _model("anthropic/claude-sonnet-4.6", "Claude Sonnet 4.6", "推理"),
            _model("google/gemini-2.5-pro", "Gemini 2.5 Pro", "多模态"),
            _model("deepseek/deepseek-v4-flash", "DeepSeek V4 Flash", "新"),
            _model("deepseek/deepseek-v4-pro", "DeepSeek V4 Pro", "强推理"),
            _model("qwen/qwen3.6-35b-a3b", "Qwen3.6 35B A3B", "开源"),
        ],
        "default_model": "openai/gpt-5.4-mini",
        "website_url": "https://openrouter.ai",
        "api_key_url": "https://openrouter.ai/keys",
        "description": "海外常用模型路由平台，一个 Key 接多家模型。",
        "requires_key": True,
    },
    {
        "id": "newapi",
        "name": "NewAPI / OneAPI",
        "category": "gateway",
        "badge": "网关",
        "base_url": "http://127.0.0.1:3000/v1",
        "endpoint_candidates": ["http://127.0.0.1:3000/v1", "https://your-newapi-domain/v1"],
        "models": [
            _model("gpt-5.4-mini", "GPT-5.4 mini", "推荐"),
            _model("deepseek-v4-flash", "DeepSeek V4 Flash", "新"),
            _model("qwen-plus-latest", "Qwen Plus Latest", "国内"),
            _model("claude-sonnet-4.6", "Claude Sonnet 4.6", "海外"),
            _model("gemini-2.5-pro", "Gemini 2.5 Pro", "海外"),
        ],
        "default_model": "gpt-5.4-mini",
        "website_url": "https://www.newapi.pro",
        "description": "自部署 API 网关，适合统一接 OpenAI/Anthropic/Gemini/国产模型。",
        "requires_key": True,
    },
    {
        "id": "groq",
        "name": "Groq",
        "category": "global",
        "badge": "海外",
        "base_url": "https://api.groq.com/openai/v1",
        "endpoint_candidates": ["https://api.groq.com/openai/v1"],
        "models": [
            _model("llama-3.3-70b-versatile", "Llama 3.3 70B Versatile", "推荐"),
            _model("llama-3.1-8b-instant", "Llama 3.1 8B Instant", "极速"),
        ],
        "default_model": "llama-3.3-70b-versatile",
        "website_url": "https://console.groq.com",
        "api_key_url": "https://console.groq.com/keys",
        "description": "Groq OpenAI-compatible 接口，响应速度快。",
        "requires_key": True,
    },
    {
        "id": "together",
        "name": "Together AI",
        "category": "global",
        "badge": "海外",
        "base_url": "https://api.together.xyz/v1",
        "endpoint_candidates": ["https://api.together.xyz/v1"],
        "models": [
            _model("deepseek-ai/DeepSeek-V4-Flash", "DeepSeek V4 Flash", "新"),
            _model("deepseek-ai/DeepSeek-V4-Pro", "DeepSeek V4 Pro", "强推理"),
            _model("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Llama 3.3 70B Turbo", "稳定"),
            _model("Qwen/Qwen3-Coder-480B-A35B-Instruct", "Qwen3 Coder 480B", "代码"),
        ],
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "website_url": "https://api.together.xyz",
        "api_key_url": "https://api.together.xyz/settings/api-keys",
        "description": "海外开源模型平台，适合 Llama/Qwen/DeepSeek 等模型。",
        "requires_key": True,
    },
    {
        "id": "ollama",
        "name": "Ollama 本地",
        "category": "local",
        "badge": "本地",
        "base_url": "http://127.0.0.1:11434/v1",
        "endpoint_candidates": ["http://127.0.0.1:11434/v1"],
        "models": [
            _model("qwen3:8b", "Qwen3 8B", "推荐"),
            _model("qwen3:14b", "Qwen3 14B", "更强"),
            _model("deepseek-r1:8b", "DeepSeek R1 8B", "推理"),
            _model("llama3.3:70b", "Llama 3.3 70B", "大模型"),
            _model("qwen2.5:7b", "Qwen2.5 7B", "兼容"),
        ],
        "default_model": "qwen3:8b",
        "website_url": "https://ollama.com",
        "description": "本地 Ollama OpenAI-compatible 接口，可不填 API Key。",
        "requires_key": False,
    },
    {
        "id": "lmstudio",
        "name": "LM Studio 本地",
        "category": "local",
        "badge": "本地",
        "base_url": "http://127.0.0.1:1234/v1",
        "endpoint_candidates": ["http://127.0.0.1:1234/v1"],
        "models": [_model("local-model", "local-model", "本地")],
        "default_model": "local-model",
        "website_url": "https://lmstudio.ai",
        "description": "LM Studio 本地兼容接口，模型名可按本地服务返回值手填。",
        "requires_key": False,
    },
    {
        "id": "custom",
        "name": "自定义 OpenAI-compatible",
        "category": "custom",
        "badge": "自定义",
        "base_url": "https://api.example.com/v1",
        "endpoint_candidates": ["https://api.example.com/v1"],
        "models": [_model("custom-model", "custom-model", "自定义")],
        "default_model": "custom-model",
        "description": "自定义第三方 API、中转 API、企业网关或私有部署。",
        "requires_key": True,
    },
]


CC_SWITCH_PROVIDER_PRESETS: List[Dict[str, Any]] = [
    _cc_provider(
        "shengsuanyun",
        "Shengsuanyun",
        "https://router.shengsuanyun.com/api/v1",
        "openai/gpt-5.5",
        website_url="https://www.shengsuanyun.com",
        badge="聚合",
    ),
    _cc_provider("patewayai", "PatewayAI", "https://api.pateway.ai/v1", "gpt-5.5", website_url="https://pateway.ai", badge="聚合"),
    _cc_provider("ccsub", "CCSub", "https://www.ccsub.net/v1", "gpt-5.5", website_url="https://www.ccsub.net", badge="聚合"),
    _cc_provider("subrouter", "SubRouter", "https://subrouter.ai/v1", "gpt-5.5", website_url="https://subrouter.ai", badge="聚合"),
    _cc_provider("unity2", "Unity2.ai", "https://api.unity2.ai", "gpt-5.5", website_url="https://unity2.ai", badge="聚合"),
    _cc_provider(
        "qiniu",
        "Qiniu",
        "https://api.qnaigc.com/bypass/openai/v1",
        "gpt-5.5",
        website_url="https://s.qiniu.com/nMvAvy",
        endpoint_candidates=[
            "https://api.qnaigc.com/bypass/openai/v1",
            "https://api.modelink.ai/bypass/openai/v1",
        ],
        badge="聚合",
    ),
    _cc_provider("fenno", "FennoAI", "https://api.fenno.ai", "gpt-5.5", website_url="https://api.fenno.ai", badge="聚合"),
    _cc_provider("zetaapi", "ZetaAPI", "https://api.zetaapi.ai/v1", "gpt-5.5", website_url="https://zetaapi.ai", badge="聚合"),
    _cc_provider("teamorouter", "TeamoRouter", "https://api.teamorouter.com/v1", "gpt-5.5", website_url="https://teamorouter.com", badge="聚合"),
    _cc_provider("amux", "Amux", "https://api.amux.ai/v1", "gpt-5.5", website_url="https://amux.ai", badge="聚合"),
    _cc_provider("code0", "Code0", "https://code0.ai/v1", "gpt-5.5", website_url="https://code0.ai", badge="聚合"),
    _cc_provider("nekocode", "NekoCode", "https://nekocode.ai/v1", "gpt-5.5", website_url="https://nekocode.ai", badge="聚合"),
    _cc_provider(
        "volcengine_agentplan",
        "火山 AgentPlan",
        "https://ark.cn-beijing.volces.com/api/coding/v3",
        "ark-code-latest",
        category="cn_official",
        badge="官方",
        website_url="https://www.volcengine.com/product/ark",
        models=[_model("ark-code-latest", "Ark Code Latest", "代码", "cc-switch Codex 预设模型。")],
    ),
    _cc_provider(
        "byteplus",
        "BytePlus",
        "https://ark.ap-southeast.bytepluses.com/api/coding/v3",
        "ark-code-latest",
        category="cn_official",
        badge="官方",
        website_url="https://www.byteplus.com/en/product/modelark",
        models=[_model("ark-code-latest", "Ark Code Latest", "代码")],
    ),
    _cc_provider(
        "deepseek",
        "DeepSeek",
        "https://api.deepseek.com",
        "deepseek-v4-flash",
        category="cn_official",
        badge="官方",
        website_url="https://platform.deepseek.com",
        api_key_url="https://platform.deepseek.com/api_keys",
        models=[
            _model("deepseek-v4-flash", "DeepSeek V4 Flash", "推荐", "cc-switch Codex 预设，1M 上下文。"),
            _model("deepseek-v4-pro", "DeepSeek V4 Pro", "强推理", "cc-switch Codex 预设，1M 上下文。"),
        ],
        description="DeepSeek 官方兼容接口，按 cc-switch 预设更新到 V4 Flash / V4 Pro。",
    ),
    _cc_provider(
        "zhipu",
        "智谱 GLM",
        "https://open.bigmodel.cn/api/coding/paas/v4",
        "glm-5.2",
        category="cn_official",
        badge="官方",
        website_url="https://open.bigmodel.cn",
        api_key_url="https://www.bigmodel.cn/claude-code",
        models=[_model("glm-5.2", "GLM-5.2", "推荐"), _model("glm-5.1", "GLM-5.1", "备用")],
    ),
    _cc_provider(
        "zhipu_en",
        "Zhipu GLM en",
        "https://api.z.ai/api/coding/paas/v4",
        "glm-5.2",
        category="cn_official",
        badge="官方",
        website_url="https://z.ai",
        models=[_model("glm-5.2", "GLM-5.2", "推荐")],
    ),
    _cc_provider(
        "qianfan_coding",
        "百度千帆 Coding Plan",
        "https://qianfan.baidubce.com/v2/coding",
        "qianfan-code-latest",
        category="cn_official",
        badge="官方",
        website_url="https://cloud.baidu.com/product/qianfan_modelbuilder",
        models=[_model("qianfan-code-latest", "Qianfan Code Latest", "代码")],
    ),
    _cc_provider(
        "dashscope",
        "阿里云百炼 Bailian",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "qwen3-coder-plus",
        category="cn_official",
        badge="官方",
        website_url="https://bailian.console.aliyun.com",
        api_key_url="https://bailian.console.aliyun.com/#/api-key",
        models=[_model("qwen3-coder-plus", "Qwen3 Coder Plus", "推荐"), _model("qwen-plus-latest", "Qwen Plus Latest", "通用")],
        api_format="openai_responses",
    ),
    _cc_provider(
        "kimi",
        "Kimi",
        "https://api.moonshot.cn/v1",
        "kimi-k2.7-code",
        category="cn_official",
        badge="官方",
        website_url="https://platform.kimi.com",
        api_key_url="https://platform.kimi.com/console/api-keys",
        models=[_model("kimi-k2.7-code", "Kimi K2.7 Code", "推荐")],
    ),
    _cc_provider(
        "kimi_coding",
        "Kimi For Coding",
        "https://api.kimi.com/coding/v1",
        "kimi-for-coding",
        category="cn_official",
        badge="官方",
        website_url="https://www.kimi.com/code",
        models=[_model("kimi-for-coding", "Kimi For Coding", "代码")],
    ),
    _cc_provider(
        "stepfun",
        "阶跃星辰 StepFun",
        "https://api.stepfun.com/step_plan/v1",
        "step-3.7-flash",
        category="cn_official",
        badge="官方",
        website_url="https://platform.stepfun.com/step-plan",
        models=[
            _model("step-3.7-flash", "Step 3.7 Flash", "推荐"),
            _model("step-3.5-flash-2603", "Step 3.5 Flash 2603", "稳定"),
            _model("step-3.5-flash", "Step 3.5 Flash", "兼容"),
        ],
    ),
    _cc_provider(
        "modelscope",
        "ModelScope 魔搭",
        "https://api-inference.modelscope.cn/v1",
        "ZhipuAI/GLM-5.1",
        badge="聚合",
        website_url="https://modelscope.cn",
        api_key_url="https://modelscope.cn/my/myaccesstoken",
        models=[_model("ZhipuAI/GLM-5.1", "ZhipuAI / GLM-5.1", "推荐")],
    ),
    _cc_provider("longcat", "LongCat", "https://api.longcat.chat/openai/v1", "LongCat-2.0-Preview", category="cn_official", badge="官方", website_url="https://longcat.chat/platform", models=[_model("LongCat-2.0-Preview", "LongCat 2.0 Preview", "新")], api_format="openai_responses"),
    _cc_provider("minimax", "MiniMax", "https://api.minimaxi.com/v1", "MiniMax-M3", category="cn_official", badge="官方", website_url="https://platform.minimaxi.com", models=[_model("MiniMax-M3", "MiniMax-M3", "推荐")], api_format="openai_responses"),
    _cc_provider("bailing", "BaiLing", "https://api.tbox.cn/api/llm/v1", "Ling-2.6-1T", category="cn_official", badge="官方", website_url="https://ling.tbox.cn/open", models=[_model("Ling-2.6-1T", "Ling-2.6-1T", "推荐")]),
    _cc_provider("xiaomi_mimo", "Xiaomi MiMo", "https://api.xiaomimimo.com/v1", "mimo-v2.5-pro", category="cn_official", badge="官方", website_url="https://platform.xiaomimimo.com", models=[_model("mimo-v2.5-pro", "MiMo V2.5 Pro", "推荐"), _model("mimo-v2.5", "MiMo V2.5", "多模态")], api_format="openai_responses"),
    _cc_provider("siliconflow", "硅基流动 SiliconFlow", "https://api.siliconflow.cn/v1", "Pro/MiniMaxAI/MiniMax-M2.7", badge="聚合", website_url="https://siliconflow.cn", models=[_model("Pro/MiniMaxAI/MiniMax-M2.7", "Pro / MiniMax M2.7", "推荐"), _model("deepseek-ai/DeepSeek-V4-Flash", "DeepSeek V4 Flash", "候选")]),
    _cc_provider("novita", "Novita AI", "https://api.novita.ai/openai/v1", "zai-org/glm-5.1", badge="聚合", website_url="https://novita.ai", models=[_model("zai-org/glm-5.1", "GLM-5.1", "推荐")]),
    _cc_provider("nvidia", "Nvidia", "https://integrate.api.nvidia.com/v1", "moonshotai/kimi-k2.5", badge="聚合", website_url="https://build.nvidia.com", models=[_model("moonshotai/kimi-k2.5", "Kimi K2.5", "推荐")]),
    _cc_provider(
        "opencode_go",
        "OpenCode Go",
        "https://opencode.ai/zen/go/v1",
        "glm-5.2",
        category="third_party",
        badge="第三方",
        website_url="https://opencode.ai/go",
        models=[
            _model("glm-5.2", "GLM 5.2", "推荐"),
            _model("glm-5.1", "GLM 5.1", "备用"),
            _model("kimi-k2.7-code", "Kimi K2.7 Code", "代码"),
            _model("deepseek-v4-pro", "DeepSeek V4 Pro", "强推理"),
            _model("deepseek-v4-flash", "DeepSeek V4 Flash", "快速"),
            _model("mimo-v2.5-pro", "MiMo V2.5 Pro", "长上下文"),
        ],
    ),
    _cc_provider("aihubmix", "AiHubMix", "https://aihubmix.com/v1", "gpt-5.5", badge="聚合", website_url="https://aihubmix.com", endpoint_candidates=["https://aihubmix.com/v1", "https://api.aihubmix.com/v1"]),
    _cc_provider("cherryin", "CherryIN", "https://open.cherryin.net/v1", "openai/gpt-5.5", badge="聚合", website_url="https://open.cherryin.ai"),
    _cc_provider("dmxapi", "DMXAPI", "https://www.dmxapi.cn/v1", "gpt-5.5", badge="聚合", website_url="https://www.dmxapi.cn"),
    _cc_provider("packycode", "PackyCode", "https://www.packyapi.com/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://www.packyapi.com", endpoint_candidates=["https://www.packyapi.com/v1", "https://api-slb.packyapi.com/v1"]),
    _cc_provider("apikeyfun", "APIKEY.FUN", "https://api.apikey.fun/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://apikey.fun", api_format="openai_responses"),
    _cc_provider("apinebula", "APINebula", "https://apinebula.com/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://apinebula.com", api_format="openai_responses"),
    _cc_provider("atlascloud", "AtlasCloud", "https://api.atlascloud.ai/v1", "zai-org/glm-5.1", badge="聚合", website_url="https://www.atlascloud.ai/console/coding-plan", models=[_model("zai-org/glm-5.1", "GLM 5.1", "推荐")]),
    _cc_provider("sudocode", "SudoCode", "https://sudocode.us/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://sudocode.us", endpoint_candidates=["https://sudocode.us/v1", "https://sudocode.run/v1"], api_format="openai_responses"),
    _cc_provider("claudecn", "ClaudeCN", "https://claudecn.top/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://claudecn.top"),
    _cc_provider("runapi", "RunAPI", "https://runapi.co/v1", "gpt-5.5", badge="聚合", website_url="https://runapi.co"),
    _cc_provider("relaxycode", "RelaxyCode", "https://www.relaxycode.com/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://www.relaxycode.com"),
    _cc_provider("cubence", "Cubence", "https://api.cubence.com/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://cubence.com", endpoint_candidates=["https://api.cubence.com/v1", "https://api-cf.cubence.com/v1", "https://api-dmit.cubence.com/v1", "https://api-bwg.cubence.com/v1"]),
    _cc_provider("aigocode", "AIGoCode", "https://api.aigocode.com", "gpt-5.5", category="third_party", badge="第三方", website_url="https://aigocode.com"),
    _cc_provider("rightcode", "RightCode", "https://right.codes/codex/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://www.right.codes"),
    _cc_provider("aicodemirror", "AICodeMirror", "https://api.aicodemirror.com/api/codex/backend-api/codex", "gpt-5.5", category="third_party", badge="第三方", website_url="https://www.aicodemirror.com", endpoint_candidates=["https://api.aicodemirror.com/api/codex/backend-api/codex", "https://api.claudecode.net.cn/api/codex/backend-api/codex"]),
    _cc_provider("crazyrouter", "CrazyRouter", "https://cn.crazyrouter.com/v1", "gpt-5.5", badge="聚合", website_url="https://www.crazyrouter.com"),
    _cc_provider("sssaicode", "SSSAiCode", "https://node-hk.sssaicodeapi.com/api/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://sssaicodeapi.com", endpoint_candidates=["https://node-hk.sssaicodeapi.com/api/v1", "https://node-hk.sssaiapi.com/api/v1", "https://node-cf.sssaicodeapi.com/api/v1"]),
    _cc_provider("compshare", "Compshare", "https://api.modelverse.cn/v1", "gpt-5.5", badge="聚合", website_url="https://www.compshare.cn"),
    _cc_provider("compshare_coding", "Compshare Coding Plan", "https://cp.compshare.cn/v1", "gpt-5.5", badge="聚合", website_url="https://www.compshare.cn"),
    _cc_provider("micu", "Micu", "https://www.micuapi.ai/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://www.micuapi.ai"),
    _cc_provider("etok", "ETok.ai", "https://api.etok.ai/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://etok.ai"),
    _cc_provider("eflowcode", "E-FlowCode", "https://e-flowcode.cc/v1", "gpt-5.5", category="third_party", badge="第三方", website_url="https://e-flowcode.cc"),
    _cc_provider("pipellm", "PIPELLM", "https://cc-api.pipellm.ai/v1", "gpt-5.5", badge="聚合", website_url="https://code.pipellm.ai"),
    _cc_provider("therouter", "TheRouter", "https://api.therouter.ai/v1", "openai/gpt-5.3-codex", badge="聚合", website_url="https://therouter.ai"),
]


def _merge_provider_presets(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order: List[str] = []
    merged: Dict[str, Dict[str, Any]] = {}
    for group in groups:
        for provider in group:
            provider_id = provider.get("id")
            if not provider_id:
                continue
            if provider_id not in merged:
                order.append(provider_id)
                merged[provider_id] = dict(provider)
            else:
                current = dict(merged[provider_id])
                current.update(provider)
                merged[provider_id] = current

    custom = merged.pop("custom", None)
    ordered = [merged[provider_id] for provider_id in order if provider_id in merged]
    if custom:
        ordered.append(custom)
    return ordered


AI_PROVIDER_PRESETS = _merge_provider_presets(AI_PROVIDER_PRESETS, CC_SWITCH_PROVIDER_PRESETS)


@dataclass
class AIConfig:
    provider: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-5.4-mini"
    temperature: float = 0.2
    timeout: int = 60
    max_tool_rounds: int = 5
    enabled: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "AIConfig":
        data = data or {}
        return cls(
            provider=_normalize_provider(data.get("provider") or "openai"),
            base_url=str(data.get("base_url") or "https://api.openai.com/v1").rstrip("/"),
            api_key=str(data.get("api_key") or ""),
            model=str(data.get("model") or "gpt-5.4-mini"),
            temperature=_clamp_float(data.get("temperature", 0.2), 0.0, 2.0),
            timeout=_clamp_int(data.get("timeout"), 5, 300, 60),
            max_tool_rounds=_clamp_int(data.get("max_tool_rounds"), 1, 10, 5),
            enabled=bool(data.get("enabled", False)),
        )

    def to_dict(self, mask_key: bool = False) -> Dict[str, Any]:
        api_key = self.api_key
        if mask_key and api_key:
            api_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "********"
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "api_key": api_key,
            "model": self.model,
            "temperature": self.temperature,
            "timeout": self.timeout,
            "max_tool_rounds": self.max_tool_rounds,
            "enabled": self.enabled,
        }

    def validate(self) -> tuple[bool, str]:
        if not self.provider:
            return False, "请选择模型供应商"
        if not self.base_url.startswith(("http://", "https://")):
            return False, "端点必须以 http:// 或 https:// 开头"
        if not self.model:
            return False, "请填写模型名称"
        if not self.api_key and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            return False, "请填写 API Key"
        return True, ""


def get_provider_presets() -> List[Dict[str, Any]]:
    return [dict(item) for item in AI_PROVIDER_PRESETS]


def _clamp_float(value: Any, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(parsed, maximum))


def _clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _normalize_provider(value: Any) -> str:
    provider = str(value or "openai").strip()
    if provider == "openai_compatible":
        return "openai"
    return provider or "openai"
