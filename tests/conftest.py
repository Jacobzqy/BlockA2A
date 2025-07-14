# tests/conftest.py
import os

# 设置 solcx 缓存目录为你有权限的路径
os.environ["SOLCX_CACHE_DIR"] = "/home/zlp/.solcx"

import solcx

# 可选：确保所需的版本已经安装
solcx.install_solc("0.8.23")
