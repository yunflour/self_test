#!/bin/bash
#
# batch_run.sh - 低内存批量执行脚本
# 顺序执行 kiro_full_flow_cn.py，避免并发导致的内存占用过高
# 执行完成后，将成功的账号文件统一移入指定文件夹
#

set -e

# ============ 配置区域 ============
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="${SCRIPT_DIR}/kiro_full_flow_cn.py"
DATA_DIR="${SCRIPT_DIR}/data"
SUCCESS_DIR="${DATA_DIR}/success_$(date +%Y%m%d_%H%M%S)"

# 执行次数（可通过参数覆盖）
COUNT=${1:-10}

# 执行间隔（秒），默认随机 5-30 秒，避免过于频繁
# 如果设置了 KIRO_INTERVAL 环境变量则使用固定值
if [[ -z "$KIRO_INTERVAL" ]]; then
    RANDOM_INTERVAL=1
else
    RANDOM_INTERVAL=0
    INTERVAL=$KIRO_INTERVAL
fi

# Python 解释器
PYTHON_EXE=${KIRO_PYTHON:-python3}
# ==================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${BLUE}[INFO]${NC} $1"
}

log_ok() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[OK]${NC} $1"
}

log_fail() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARN]${NC} $1"
}

# 检查 Python 脚本是否存在
check_script() {
    if [[ ! -f "$PYTHON_SCRIPT" ]]; then
        log_fail "找不到脚本: $PYTHON_SCRIPT"
        exit 1
    fi
}

# 创建目录
setup_dirs() {
    mkdir -p "$DATA_DIR"
    mkdir -p "$SUCCESS_DIR"
    log_info "数据目录: $DATA_DIR"
    log_info "成功文件目录: $SUCCESS_DIR"
}

# 从结果文件中提取状态
extract_status() {
    local result_file="$1"
    if [[ ! -f "$result_file" ]]; then
        echo "no_result_file"
        return
    fi

    # 使用 Python 解析 JSON（兼容性更好）
    $PYTHON_EXE -c "
import json
import sys
try:
    with open('$result_file', 'r', encoding='utf-8') as f:
        data = json.load(f)
    verify = data.get('credential_verify', {})
    if isinstance(verify, dict):
        status = verify.get('status', 'unknown')
    else:
        status = 'unknown'
    print(status)
except Exception as e:
    print('parse_error')
" 2>/dev/null
}

# 从结果文件中提取邮箱
extract_email() {
    local result_file="$1"
    if [[ ! -f "$result_file" ]]; then
        echo ""
        return
    fi

    $PYTHON_EXE -c "
import json
try:
    with open('$result_file', 'r', encoding='utf-8') as f:
        data = json.load(f)
    token_output = data.get('token_output', {})
    if isinstance(token_output, dict):
        print(token_output.get('email', ''))
    else:
        print('')
except:
    print('')
" 2>/dev/null
}

# 从结果文件中提取 token 文件路径
extract_token_file() {
    local result_file="$1"
    if [[ ! -f "$result_file" ]]; then
        echo ""
        return
    fi

    $PYTHON_EXE -c "
import json
try:
    with open('$result_file', 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(data.get('token_output_file', ''))
except:
    print('')
" 2>/dev/null
}

# 执行单次任务
run_single() {
    local idx="$1"
    local total="$2"
    local run_id="batch_${idx}"

    log_info "[${idx}/${total}] 开始执行任务 (run_id: ${run_id})"

    # 设置环境变量
    export KIRO_RUN_ID="$run_id"

    # 执行脚本，捕获输出
    local output
    local exit_code
    output=$($PYTHON_EXE "$PYTHON_SCRIPT" 2>&1) || exit_code=$?

    # 从输出中提取结果文件路径
    local result_file
    result_file=$(echo "$output" | grep -oP '完整结果文件已保存：\K.*' | tail -1)

    # 检查结果
    if [[ -z "$result_file" ]] || [[ ! -f "$result_file" ]]; then
        log_fail "[${idx}/${total}] 未找到结果文件"
        echo "no_result_file" >> "$STATUS_FILE"
        return 1
    fi

    local status
    status=$(extract_status "$result_file")

    local email
    email=$(extract_email "$result_file")

    case "$status" in
        ok)
            log_ok "[${idx}/${total}] 执行成功! 邮箱: ${email}"
            echo "ok|$result_file|$email" >> "$STATUS_FILE"

            # 复制 token 文件到成功目录
            local token_file
            token_file=$(extract_token_file "$result_file")
            if [[ -n "$token_file" ]] && [[ -f "$token_file" ]]; then
                cp "$token_file" "$SUCCESS_DIR/"
                log_info "已复制 token 文件到: $SUCCESS_DIR/"
            fi
            ;;
        blocked_or_invalid)
            log_fail "[${idx}/${total}] 账号被阻止或无效"
            echo "blocked|$result_file|$email" >> "$STATUS_FILE"
            ;;
        *)
            log_warn "[${idx}/${total}] 状态未知: $status"
            echo "unknown|$result_file|$email" >> "$STATUS_FILE"
            ;;
    esac

    return 0
}

# 打印汇总
print_summary() {
    local total="$1"

    echo ""
    echo "============================================"
    echo "               执行结果汇总"
    echo "============================================"

    local ok_count=0
    local blocked_count=0
    local failed_count=0
    local unknown_count=0

    if [[ -f "$STATUS_FILE" ]]; then
        ok_count=$(grep -c "^ok|" "$STATUS_FILE" 2>/dev/null || echo 0)
        blocked_count=$(grep -c "^blocked|" "$STATUS_FILE" 2>/dev/null || echo 0)
        failed_count=$(grep -c "^no_result_file" "$STATUS_FILE" 2>/dev/null || echo 0)
        unknown_count=$(grep -c "^unknown|" "$STATUS_FILE" 2>/dev/null || echo 0)
    fi

    echo "  总执行次数: $total"
    echo -e "  ${GREEN}成功 (ok): $ok_count${NC}"
    echo -e "  ${RED}被阻止 (blocked): $blocked_count${NC}"
    echo -e "  ${YELLOW}未知状态: $unknown_count${NC}"
    echo -e "  ${RED}执行失败: $failed_count${NC}"
    echo ""
    echo "  成功文件目录: $SUCCESS_DIR"
    echo "  状态记录文件: $STATUS_FILE"
    echo "============================================"

    # 打印成功账号列表
    if [[ $ok_count -gt 0 ]] && [[ -f "$STATUS_FILE" ]]; then
        echo ""
        echo "成功的账号:"
        grep "^ok|" "$STATUS_FILE" | while IFS='|' read -r status result_file email; do
            echo -e "  ${GREEN}✓${NC} $email"
        done
    fi
}

# 主函数
main() {
    echo ""
    echo "============================================"
    echo "     Kiro 批量执行脚本 (顺序模式)"
    echo "============================================"
    echo "  执行次数: $COUNT"
    if [[ "$RANDOM_INTERVAL" == "1" ]]; then
        echo "  执行间隔: 随机 5-30 秒"
    else
        echo "  执行间隔: ${INTERVAL}s (固定)"
    fi
    echo "  Python: $PYTHON_EXE"
    echo "============================================"
    echo ""

    check_script
    setup_dirs

    # 状态记录文件
    STATUS_FILE="${DATA_DIR}/batch_status_$(date +%Y%m%d_%H%M%S).txt"
    touch "$STATUS_FILE"

    local start_time
    start_time=$(date +%s)

    # 循环执行
    for ((i=1; i<=COUNT; i++)); do
        run_single "$i" "$COUNT"

        # 最后一次不需要等待
        if [[ $i -lt $COUNT ]]; then
            if [[ "$RANDOM_INTERVAL" == "1" ]]; then
                INTERVAL=$((RANDOM % 26 + 5))  # 5-30秒随机
            fi
            log_info "等待 ${INTERVAL}s 后继续..."
            sleep "$INTERVAL"
        fi
    done

    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    print_summary "$COUNT"

    echo ""
    log_info "总耗时: ${elapsed}s"
    log_info "完成!"
}

# 显示帮助
show_help() {
    echo "用法: $0 [COUNT]"
    echo ""
    echo "参数:"
    echo "  COUNT    执行次数 (默认: 10)"
    echo ""
    echo "环境变量:"
    echo "  KIRO_INTERVAL   执行间隔秒数 (默认: 随机 5-30 秒)"
    echo "  KIRO_PYTHON     Python 解释器路径 (默认: python3)"
    echo ""
    echo "示例:"
    echo "  $0 20                    # 执行 20 次，间隔随机 5-30 秒"
    echo "  KIRO_INTERVAL=10 $0 20   # 间隔固定 10 秒，执行 20 次"
}

# 检查参数
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

main
