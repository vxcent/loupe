#!/usr/bin/env python3
"""Idempotent setup for the real-Cybench integration.

The Cybench clone is gitignored, so the edits we make to it aren't versioned here.
This script reproduces them on a fresh clone:
  1. register deepseek-ai/DeepSeek-V4-Pro in agent_spec.py (enum + NonHELMMapping
     for routing + TokenizerMapping because run_task.py builds --model choices from
     the tokenizer mapping keys)
  2. drop the TTY flag in run_task.sh (-it -> -i) so it runs headless/background
  3. copy TOGETHER_API_KEY from ../.env into cybench/.env

    git clone --depth 1 https://github.com/andyzorigin/cybench.git cybench
    python experiments/cyber/setup_cybench.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CYB = os.path.join(ROOT, "cybench")

ENUM_ANCHOR = '    QWEN_2_72B_INSTRUCT = "together/qwen2-72b-instruct"'
ENUM_ADD = '\n    DEEPSEEK_V4_PRO = "together/deepseek-v4-pro"'
NONHELM_ANCHOR = ('        DeploymentName.LLAMA_3_1_70B_INSTRUCT_TURBO: '
                  '"meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",\n    }')
NONHELM_ADD = ('        DeploymentName.LLAMA_3_1_70B_INSTRUCT_TURBO: '
               '"meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",\n'
               '        DeploymentName.DEEPSEEK_V4_PRO: "deepseek-ai/DeepSeek-V4-Pro",\n    }')
TOK_ANCHOR = '        DeploymentName.YI_LARGE: "01-ai/Yi-6B",\n    }'
TOK_ADD = ('        DeploymentName.YI_LARGE: "01-ai/Yi-6B",\n'
           '        DeploymentName.DEEPSEEK_V4_PRO: "deepseek-ai/DeepSeek-V4-Pro",\n    }')


def patch_agent_spec():
    p = os.path.join(CYB, "agent", "dataclasses", "agent_spec.py")
    s = open(p).read()
    if "DEEPSEEK_V4_PRO" in s:
        print("  agent_spec.py: already patched")
        return
    s = s.replace(ENUM_ANCHOR, ENUM_ANCHOR + ENUM_ADD, 1)
    s = s.replace(NONHELM_ANCHOR, NONHELM_ADD, 1)
    s = s.replace(TOK_ANCHOR, TOK_ADD, 1)
    open(p, "w").write(s)
    print("  agent_spec.py: registered deepseek-ai/DeepSeek-V4-Pro")


def patch_run_task():
    p = os.path.join(CYB, "run_task.sh")
    s = open(p).read()
    s2 = re.sub(r"\n\t-it \\\n", "\n\t-i \\\n", s)
    if s2 != s:
        open(p, "w").write(s2)
        print("  run_task.sh: -it -> -i (headless)")
    else:
        print("  run_task.sh: already headless or pattern not found")


def copy_env():
    src, dst = os.path.join(ROOT, ".env"), os.path.join(CYB, ".env")
    key = ""
    if os.path.exists(src):
        for ln in open(src):
            if ln.strip().startswith("TOGETHER_API_KEY="):
                key = ln.split("=", 1)[1].strip()
    ex = os.path.join(CYB, ".env.example")
    base = open(ex).read() if os.path.exists(ex) else "TOGETHER_API_KEY=\n"
    base = re.sub(r"TOGETHER_API_KEY=.*", f"TOGETHER_API_KEY={key}", base)
    open(dst, "w").write(base)
    print(f"  cybench/.env: TOGETHER_API_KEY {'set' if key else 'EMPTY (fill it in)'}")


def main():
    if not os.path.isdir(CYB):
        sys.exit("cybench/ not found. Clone first:\n  git clone --depth 1 "
                 "https://github.com/andyzorigin/cybench.git cybench")
    print("patching Cybench clone:")
    patch_agent_spec()
    patch_run_task()
    copy_env()
    print("done. Smoke test:\n  cd cybench && ./run_task.sh --task_dir "
          "'benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary "
          "Knowledge' --max_iterations 12 --iterations_until_hint 12 "
          "--model together/deepseek-v4-pro --easy_prompt --unguided_mode")


if __name__ == "__main__":
    main()
