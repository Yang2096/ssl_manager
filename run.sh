#!/bin/bash

make cli

# 从 .env 文件加载环境变量
ENV_FILE="$(dirname "$0")/.env"

if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # 跳过空行和注释行
        [[ -z "$key" || "$key" =~ ^# ]] && continue

        # 去除首尾空白
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        export "$key=$value"
        echo -e "\033[32mLoaded: [$key]\033[0m"
    done < "$ENV_FILE"
fi

# 运行 cli 并传递所有参数
./build/cli $@
