"""LLM API wrapper supporting DeepSeek (primary), GLM (Zhipu AI), OpenAI, and Qwen/DashScope."""

import os
import time
import json
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

_openai_cls = None
def _get_openai():
    global _openai_cls
    if _openai_cls is None:
        from openai import OpenAI as _OpenAI
        _openai_cls = _OpenAI
    return _openai_cls

REQUEST_TIMEOUT = 25.0  # seconds per HTTP read (streaming/chunked responses use multiple reads)
MAX_RETRIES = 2         # total attempts = MAX_RETRIES
# Worst-case per chat_with_tools() call: 25s × 2 + 1s backoff = 51s
# Worker self-kills at 65s, parent taskkills at 75s — safe margin.


class LLMClient:
    def __init__(self, model="deepseek-chat", temperature=0.3, max_tokens=2048,
                 base_url=None, api_key=None, timeout=REQUEST_TIMEOUT):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        if "deepseek" in model:
            base_url = base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
            api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        elif "glm" in model:
            base_url = base_url or os.getenv("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4/")
            api_key = api_key or os.getenv("GLM_API_KEY")
        elif "qwen" in model or "dashscope" in model:
            base_url = base_url or os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
            api_key = api_key or os.getenv("DASHSCOPE_API_KEY")
        elif "openai" in model or "gpt" in model:
            base_url = base_url or os.getenv("OPENAI_BASE_URL")
            api_key = api_key or os.getenv("OPENAI_API_KEY")
        else:
            # Fallback: use the custom endpoint configured in .env
            base_url = base_url or os.getenv("DEEPSEEK_BASE_URL")
            api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        from openai import OpenAI as _OpenAI
        # Critical: use a per-operation timeout (not just a global float).
        # A bare float timeout=N in httpx applies to each IO syscall; if the server
        # accepts the connection but never sends data, recv() can block indefinitely
        # because "connected" doesn't count toward connect timeout. We cap read at
        # self.timeout to guarantee a single HTTP round-trip takes ≤ timeout seconds.
        import httpx
        timeout_cfg = httpx.Timeout(connect=10.0, read=float(self.timeout),
                                    write=10.0, pool=10.0)
        self.client = _OpenAI(api_key=api_key, base_url=base_url, timeout=timeout_cfg)

    def _is_retryable(self, e: Exception) -> bool:
        msg = str(e).lower()
        return any(k in msg for k in ("rate", "429", "timeout", "timed out", "connection",
                                       "reset", "temporarily", "overloaded", "busy",
                                       "502", "503", "504"))

    def _retry_call(self, kwargs):
        last_err = None
        for a in range(MAX_RETRIES):
            try:
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:
                last_err = e
                if a < MAX_RETRIES - 1 and self._is_retryable(e):
                    time.sleep(min(2 ** a + a, 15))
                    continue
                raise
        raise last_err  # unreachable, satisfies linter

    def chat(self, messages, system_prompt=None, temperature=None, seed=None):
        msgs = [{"role":"system","content":system_prompt}]+messages if system_prompt else list(messages)
        kwargs = dict(model=self.model, messages=msgs,
                      temperature=temperature or self.temperature, max_tokens=self.max_tokens)
        if seed is not None: kwargs["seed"]=seed
        resp = self._retry_call(kwargs)
        return resp.choices[0].message.content.strip()

    def chat_with_tools(self, messages, tools, system_prompt=None,
                        temperature=None, seed=None):
        msgs = [{"role":"system","content":system_prompt}]+messages if system_prompt else list(messages)
        kwargs = dict(model=self.model, messages=msgs, tools=tools, tool_choice="auto",
                      temperature=temperature or self.temperature, max_tokens=self.max_tokens)
        if seed is not None: kwargs["seed"]=seed
        resp = self._retry_call(kwargs)
        msg = resp.choices[0].message
        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}
            tool_calls.append({"id": tc.id, "name": tc.function.name, "arguments": args})
        return {"content": msg.content or "", "tool_calls": tool_calls}
