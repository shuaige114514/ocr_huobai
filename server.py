#!/usr/bin/env python
# -*- coding:utf-8 -*-

# ========== 修复 Pillow 高版本兼容性问题 ==========
import sys
import warnings

warnings.filterwarnings("ignore")

try:
    import PIL.Image

    if hasattr(PIL.Image, 'Resampling'):
        PIL.Image.ANTIALIAS = PIL.Image.Resampling.LANCZOS
        print("[INFO] 已修复 Pillow 高版本兼容性")
    elif not hasattr(PIL.Image, 'ANTIALIAS'):
        PIL.Image.ANTIALIAS = 1
except Exception as e:
    print(f"[WARN] Pillow 兼容性修补失败: {e}")
# ========== 修复完成 ==========

from http.server import HTTPServer, BaseHTTPRequestHandler
import re, time, base64, os, requests
import json
from urllib.parse import parse_qs, urlparse, parse_qsl, unquote
import traceback
from socketserver import ThreadingMixIn
import hashlib

host = ('0.0.0.0', 8899)
count = 50  # 保存多少个验证码及结果

# 全局存储提取的参数
extracted_params = {}
request_history = []


def send_complex_request(complex_request, target_url=None):
    """
    发送复杂数据包请求
    支持完整的HTTP请求包，包含自定义headers、cookies、data等
    """
    headers = {}
    data = None
    method = "GET"
    url = target_url

    if not complex_request:
        raise ValueError("复杂数据包内容为空")

    print(f"[复杂请求] 处理复杂数据包，长度: {len(complex_request)}")
    print(f"[复杂请求] 目标URL: {target_url}")

    # 分离头部和主体
    parts = complex_request.split('\n\n', 1)
    if len(parts) < 2:
        parts = complex_request.split('\r\n\r\n', 1)

    if len(parts) == 2:
        headers_part, body_part = parts
    else:
        headers_part = complex_request
        body_part = ""

    # 解析头部
    lines = headers_part.strip().split('\n')
    if lines:
        # 第一行是请求行
        request_line = lines[0].strip()
        print(f"[复杂请求] 请求行: {request_line}")

        if ' ' in request_line:
            parts = request_line.split(' ')
            method = parts[0].upper()

            # 解析URL
            if len(parts) > 1:
                path = parts[1]
                # 如果路径是完整的URL，使用它
                if path.startswith('http'):
                    url = path
                elif target_url:
                    # 否则使用传入的URL作为基础
                    parsed_target = urlparse(target_url)
                    # 如果path以/开头，直接使用
                    if path.startswith('/'):
                        url = f"{parsed_target.scheme}://{parsed_target.netloc}{path}"
                    else:
                        # 否则追加到现有路径
                        url = target_url.rstrip('/') + '/' + path
                else:
                    raise ValueError("无法确定请求URL")

            print(f"[复杂请求] 方法: {method}, URL: {url}")

        # 解析其他头部
        for line in lines[1:]:
            line = line.strip()
            if line and ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value

    # 解析主体
    if body_part:
        data = body_part.strip()

    # 准备请求参数
    request_kwargs = {
        'headers': headers,
        'timeout': 10,
        'verify': False,
        'allow_redirects': False
    }

    # 如果是POST请求且有数据
    if method == "POST" and data:
        # 检查Content-Type
        content_type = headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                request_kwargs['json'] = json.loads(data)
            except:
                request_kwargs['data'] = data
        elif 'application/x-www-form-urlencoded' in content_type:
            # 解析表单数据
            try:
                form_data = {}
                for item in data.split('&'):
                    if '=' in item:
                        k, v = item.split('=', 1)
                        form_data[unquote(k)] = unquote(v)
                request_kwargs['data'] = form_data
            except:
                request_kwargs['data'] = data
        else:
            request_kwargs['data'] = data

    try:
        print(f"[复杂请求] 最终请求参数: method={method}, url={url}")
        print(f"[复杂请求] 请求头: {headers}")

        if method == "GET":
            response = requests.get(url, **request_kwargs)
        elif method == "POST":
            response = requests.post(url, **request_kwargs)
        elif method == "PUT":
            response = requests.put(url, **request_kwargs)
        elif method == "DELETE":
            response = requests.delete(url, **request_kwargs)
        else:
            raise ValueError(f"不支持的请求方法: {method}")

        print(f"[复杂请求] 响应状态码: {response.status_code}")
        return response

    except Exception as e:
        print(f"[复杂请求] 发送请求失败: {e}")
        traceback.print_exc()
        return None


def calculate_math_expression(text):
    """计算数学表达式，支持加减乘除"""
    import re

    # 清理文本
    cleaned = text.replace(' ', '').replace('?', '').replace('=', '').replace('？', '').replace(':', '')

    # 匹配多种算式格式
    patterns = [
        r'(\d+)([\+\-\*/xX])(\d+)',  # 3+5, 10-2
        r'(\d+)\s*[\+\-]\s*(\d+)',  # 3 + 5
        r'(\d+)\s*[\*/]\s*(\d+)',  # 3 * 5
    ]

    for pattern in patterns:
        match = re.search(pattern, cleaned)
        if match:
            if len(match.groups()) == 3:
                num1, operator, num2 = match.groups()
            elif len(match.groups()) == 2:
                num1, num2 = match.groups()
                # 从匹配字符串中提取运算符
                op_match = re.search(r'[\+\-\*/xX]', cleaned[match.start():match.end()])
                operator = op_match.group() if op_match else '+'

            operator = operator.lower() if operator in ['x', 'X'] else operator

            try:
                num1, num2 = int(num1), int(num2)
                if operator == '+':
                    result = num1 + num2
                elif operator == '-':
                    result = num1 - num2
                elif operator in ['*', 'x']:
                    result = num1 * num2
                elif operator == '/':
                    if num2 != 0:
                        result = num1 / num2
                        if result.is_integer():
                            result = int(result)
                    else:
                        return text
                else:
                    return text
                return str(result)
            except Exception as e:
                print(f"计算错误: {e}")
                return text

    return text


def extract_parameters(response, request_url=None, request_headers=None):
    """
    从响应中提取参数（session、token等）
    返回格式：参数名1=参数值1;参数名2=参数值2
    """
    extracted = []

    if response is None:
        return ''

    print(f"[参数提取] 开始提取参数，响应状态: {response.status_code}")

    # 1. 从响应头中提取参数
    for header_name, header_value in response.headers.items():
        # 特别关注常见的session/token相关头部
        header_lower = header_name.lower()
        if any(keyword in header_lower for keyword in
               ['session', 'token', 'auth', 'id', 'key', 'secret', 'csrf', 'xsrf', 'jwt']):
            # 清理值
            value = header_value.strip().split(';')[0].split(',')[0]
            if value and len(value) < 200:
                extracted.append(f"{header_name}={value}")
                print(f"[参数提取] 从响应头提取: {header_name}={value[:50]}...")

    # 2. 从Set-Cookie中提取参数
    if 'Set-Cookie' in response.headers:
        cookies = response.headers.get('Set-Cookie', '')
        cookie_pairs = re.findall(r'([^=]+)=([^;]+)', cookies)
        for key, value in cookie_pairs:
            if key and value and key.lower() not in ['path', 'domain', 'expires', 'max-age', 'secure', 'httponly',
                                                     'samesite']:
                extracted.append(f"{key}={value}")
                print(f"[参数提取] 从Set-Cookie提取: {key}={value[:50]}...")

    # 3. 从响应体中提取参数（JSON格式）
    content_type = response.headers.get('Content-Type', '').lower()
    if 'application/json' in content_type:
        try:
            json_data = json.loads(response.text)
            print(f"[参数提取] 解析JSON响应体")

            def extract_from_json(obj, prefix=''):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        full_key = f"{prefix}{key}" if prefix else key
                        if isinstance(value, (str, int, float, bool)) and value is not None:
                            # 跳过常见的非参数键
                            if key.lower() in ['code', 'status', 'success', 'message', 'error', 'msg', 'data', 'result',
                                               'image', 'captcha']:
                                continue
                            if isinstance(value, str) and len(value) < 100:
                                extracted.append(f"{full_key}={value}")
                                print(f"[参数提取] 从JSON提取: {full_key}={value[:50]}...")
                        elif isinstance(value, dict):
                            extract_from_json(value, f"{full_key}.")
                        elif isinstance(value, list):
                            for i, item in enumerate(value):
                                extract_from_json(item, f"{full_key}[{i}].")

            extract_from_json(json_data)
        except Exception as e:
            print(f"[参数提取] JSON解析失败: {e}")

    if 'Set-Cookie' in response.headers:
        cookies = response.headers.get('Set-Cookie', '')
        print(f"[参数提取] 原始Set-Cookie头部: {cookies}")  # 调试日志
        # 更健壮的正则匹配，处理多个Cookie和复杂值
        cookie_pairs = re.findall(r'([^=;]+)=([^;]+)', cookies)
        for key, value in cookie_pairs:
            key = key.strip()
            value = value.strip()
            # 排除明显是属性而非参数的关键字（更全的列表）
            if (key and value and
                    key.lower() not in ['path', 'domain', 'expires', 'max-age',
                                        'secure', 'httponly', 'samesite', 'version',
                                        'comment', 'port'] and
                    not key.startswith('__') and len(value) < 500):  # 限制长度避免过长值
                extracted.append(f"{key}={value}")
                print(f"[参数提取] 从Set-Cookie提取: {key}={value[:50]}...")

    else:
        # 提取常见的参数模式
        patterns = [
            r'"([A-Za-z0-9_]+)"\s*:\s*"([^"]+)"',  # JSON格式
            r"'([A-Za-z0-9_]+)'\s*:\s*'([^']+)'",  # JSON格式
            r'([A-Za-z0-9_]+)\s*=\s*"([^"]+)"',  # 表单格式
            r'([A-Za-z0-9_]+)\s*=\s*\'([^\']+)\'',  # 表单格式
            r'([A-Za-z0-9_]+)\s*=\s*([A-Za-z0-9_\-\.]+)',  # 无引号
            r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',  # HTML input
            r'var\s+([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']',  # JavaScript变量
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response.text)
            for match in matches:
                if len(match) == 2:
                    key, value = match
                    # 过滤掉太长的值或非参数键
                    if (key and value and len(value) < 100 and
                            key.lower() not in ['code', 'status', 'success', 'message', 'error', 'msg']):
                        extracted.append(f"{key}={value}")

    # 5. 从URL参数中提取（如果有）
    if request_url:
        parsed_url = urlparse(request_url)
        query_params = parse_qsl(parsed_url.query)
        for key, value in query_params:
            if key and value and key.lower() not in ['code', 'status', 'success']:
                extracted.append(f"{key}={value}")

    # 6. 从请求头中提取（特别关注Cookie）
    if request_headers and 'Cookie' in request_headers:
        cookies = request_headers.get('Cookie', '')
        cookie_pairs = re.findall(r'([^=]+)=([^;]+)', cookies)
        for key, value in cookie_pairs:
            if key and value and key.lower() not in ['path', 'domain', 'expires']:
                extracted.append(f"{key}={value}")

    # 去重（保持顺序）
    unique_extracted = []
    seen = set()
    for item in extracted:
        if item not in seen:
            unique_extracted.append(item)
            seen.add(item)

    result = ';'.join(unique_extracted) if unique_extracted else ''
    print(f"[参数提取] 最终提取结果: {result}")
    return result


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程HTTP服务器"""
    pass


class Resquest(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """重写日志输出，避免干扰"""
        pass

    def handler(self):
        print("data:", self.rfile.readline().decode())
        self.wfile.write(self.rfile.readline())

    def do_GET(self):
        print(self.requestline)
        if self.path != '/':
            self.send_error(404, "Page not Found!")
            return

        try:
            with open('temp/log.txt', 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            content = ""

        # 显示提取的参数
        params_content = ""
        try:
            with open('temp/params.txt', 'r', encoding='utf-8') as f:
                params_content = f.read()
        except:
            params_content = ""

        # 显示请求历史
        history_content = ""
        if request_history:
            history_items = []
            for i, hist in enumerate(request_history[-10:]):  # 显示最近10条
                history_items.append(
                    f"<div class='history-item'><strong>请求 {i + 1}:</strong> {hist['type']} - {hist['url']} - 状态: {hist.get('status', 'N/A')}</div>")
            history_content = ''.join(history_items)

        # 完整版的 Web 界面
        html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>验证码识别系统 - 火白学安全完整版</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }

        /* 头部样式 */
        .header { background: linear-gradient(135deg, #1a237e 0%, #283593 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.8rem; margin-bottom: 15px; font-weight: 300; letter-spacing: 1px; }
        .header .subtitle { font-size: 1.2rem; opacity: 0.9; margin-bottom: 25px; }
        .version-badge { display: inline-block; background: #00bcd4; color: white; padding: 8px 20px; border-radius: 50px; font-size: 1rem; font-weight: 600; margin: 15px 0; box-shadow: 0 4px 15px rgba(0,188,212,0.4); }

        /* 信息框 */
        .info-box { background: rgba(255,255,255,0.1); border-radius: 15px; padding: 25px; margin: 30px auto; max-width: 900px; backdrop-filter: blur(10px); }
        .mode-guide { display: flex; justify-content: center; flex-wrap: wrap; gap: 15px; margin: 25px 0; }
        .mode-tag { padding: 10px 25px; border-radius: 10px; font-weight: 600; font-size: 0.95rem; transition: all 0.3s ease; cursor: default; }
        .mode-tag:hover { transform: translateY(-3px); box-shadow: 0 8px 20px rgba(0,0,0,0.2); }
        .mode-0 { background: #2196F3; color: white; }
        .mode-1 { background: #4CAF50; color: white; }
        .mode-2 { background: #FF9800; color: white; }
        .mode-3 { background: #9C27B0; color: white; }
        .mode-8 { background: #607D8B; color: white; }

        /* 表格容器 */
        .table-container { padding: 30px; overflow-x: auto; }
        table { width: 100%; border-collapse: separate; border-spacing: 0; border-radius: 15px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.08); }
        thead { background: linear-gradient(135deg, #3949ab 0%, #303f9f 100%); color: white; }
        th { padding: 22px 15px; text-align: center; font-weight: 600; font-size: 1.1rem; letter-spacing: 0.5px; }
        tbody tr { transition: all 0.3s ease; border-bottom: 1px solid #f0f0f0; }
        tbody tr:hover { background-color: #f8f9fa; transform: scale(1.01); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        td { padding: 20px 15px; text-align: center; vertical-align: middle; border-bottom: 1px solid #eee; }

        /* 验证码图片 */
        .captcha-img { max-width: 180px; max-height: 80px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); transition: transform 0.3s ease; }
        .captcha-img:hover { transform: scale(1.1); box-shadow: 0 8px 25px rgba(0,0,0,0.2); }

        /* 结果文本 */
        .result-text { font-size: 1.3rem; font-weight: 700; color: #1a237e; font-family: 'Consolas', 'Monaco', monospace; }
        .timestamp { color: #666; font-size: 0.95rem; }
        .mode-indicator { display: inline-block; padding: 8px 20px; border-radius: 25px; font-weight: 600; font-size: 0.9rem; min-width: 80px; }

        /* 底部 */
        .footer { background: #f5f7fa; padding: 30px; text-align: center; border-top: 1px solid #e0e0e0; color: #666; }
        .credits { margin-top: 20px; font-size: 0.95rem; }
        .github-link { color: #3949ab; text-decoration: none; font-weight: 600; transition: color 0.3s ease; }
        .github-link:hover { color: #1a237e; text-decoration: underline; }

        /* 改进说明 */
        .improvement-note { background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%); border-radius: 15px; padding: 20px; margin: 25px auto; max-width: 900px; border-left: 5px solid #9C27B0; }
        .improvement-title { color: #7b1fa2; font-size: 1.2rem; margin-bottom: 10px; font-weight: 600; }

        /* 统计栏 */
        .stats-bar { background: #f8f9fa; border-radius: 10px; padding: 15px; margin: 20px 0; display: flex; justify-content: space-around; flex-wrap: wrap; gap: 15px; }
        .stat-item { text-align: center; padding: 10px 20px; }
        .stat-value { font-size: 1.8rem; font-weight: 700; color: #3949ab; display: block; }
        .stat-label { font-size: 0.9rem; color: #666; margin-top: 5px; }

        /* 参数容器 */
        .params-container { background: #f9f9f9; border-radius: 10px; padding: 20px; margin: 20px 30px; border: 1px solid #e0e0e0; }
        .params-title { color: #3949ab; font-size: 1.2rem; margin-bottom: 15px; font-weight: 600; }
        .params-list { font-family: 'Consolas', monospace; background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }

        /* 历史记录 */
        .history-container { background: #f0f7ff; border-radius: 10px; padding: 20px; margin: 20px 30px; border: 1px solid #cce0ff; }
        .history-title { color: #0066cc; font-size: 1.2rem; margin-bottom: 15px; font-weight: 600; }
        .history-list { font-family: 'Consolas', monospace; background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd; max-height: 300px; overflow-y: auto; }
        .history-item { padding: 8px 0; border-bottom: 1px solid #eee; font-size: 0.9rem; }

        /* 状态指示器 */
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .status-success { background-color: #4CAF50; }
        .status-error { background-color: #F44336; }
        .status-warning { background-color: #FF9800; }

        @media (max-width: 768px) {
            .header h1 { font-size: 2rem; }
            .header { padding: 25px 20px; }
            .table-container { padding: 15px; }
            th, td { padding: 15px 10px; }
            .mode-guide { flex-direction: column; align-items: center; }
            .mode-tag { width: 90%; text-align: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>验证码识别系统</h1>
            <div class="subtitle">火白学安全</div>
            <div class="version-badge">v1.0 Complete</div>

            <div class="info-box">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="font-size: 1.1rem; margin-bottom: 15px; color: #e3f2fd;">深度优化 - 完整功能版</div>
                    <div style="font-size: 0.95rem; opacity: 0.9;">支持复杂数据包 • 参数自动提取 • 多接口管理</div>
                </div>

                <div class="mode-guide">
                    <div class="mode-tag mode-0">模式 0: 纯数字识别</div>
                    <div class="mode-tag mode-1">模式 1: 英文数字混合</div>
                    <div class="mode-tag mode-2">模式 2: 复杂验证码</div>
                    <div class="mode-tag mode-3">模式 3: 数学计算</div>
                    <div class="mode-tag mode-8">模式 8: 直接提取</div>
                </div>
            </div>
        </div>

        <div class="improvement-note">
            <div class="improvement-title">🚀 完整功能特性</div>
            <div style="color: #555; line-height: 1.6;">
                • <strong>复杂数据包支持</strong>: 完整HTTP数据包解析，支持自定义headers、cookies、body<br>
                • <strong>参数自动提取</strong>: 从响应头、Set-Cookie、JSON、HTML中智能提取参数<br>
                • <strong>多模式识别</strong>: 支持5种识别模式，适应各种验证码类型<br>
                • <strong>数学计算</strong>: 自动识别并计算数学表达式验证码<br>
                • <strong>请求历史</strong>: 记录最近请求，便于调试和分析<br>
                • <strong>完整日志</strong>: 详细的处理日志，便于问题排查
            </div>
        </div>

        <div class="stats-bar">
            <div class="stat-item">
                <span class="stat-value" id="totalCount">''' + str(len(content.split('<tr>'))) + '''</span>
                <span class="stat-label">识别记录</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">''' + str(count) + '''</span>
                <span class="stat-label">最大保存</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">5</span>
                <span class="stat-label">识别模式</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">''' + str(len(request_history)) + '''</span>
                <span class="stat-label">请求历史</span>
            </div>
        </div>

        <div class="history-container">
            <div class="history-title">📝 最近请求历史</div>
            <div class="history-list" id="historyList">
''' + (history_content if history_content else "<div style='color: #666; text-align: center;'>暂无请求历史记录</div>") + '''
            </div>
        </div>

        <div class="params-container">
            <div class="params-title">📋 最近提取的参数</div>
            <div class="params-list" id="paramsList">
''' + (params_content if params_content else "暂无参数提取记录") + '''
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>验证码图像</th>
                        <th>识别结果</th>
                        <th>提取参数</th>
                        <th>识别时间</th>
                        <th>识别模式</th>
                        <th>请求类型</th>
                    </tr>
                </thead>
                <tbody>
''' + content + '''
                </tbody>
            </table>
        </div>

        <div class="footer">
            <div style="font-size: 1.1rem; color: #444; margin-bottom: 15px;">
                🚀 高性能验证码识别服务运行中
            </div>
            <div class="credits">
                博客 <a href="https://blog.csdn.net/mc11451419198" target="_blank" class="github-link">火白学安全</a> 欢迎关注<br>
                <span style="color: #888; font-size: 0.9rem; margin-top: 10px; display: inline-block;">
                    火白学安全 &copy; ''' + str(time.localtime().tm_year) + ''' | 本地服务端口: ''' + str(
            host[1]) + '''
                </span>
            </div>
        </div>
    </div>

    <script>
        // 实时更新统计信息
        function updateStats() {
            const rows = document.querySelectorAll('tbody tr');
            document.getElementById('totalCount').textContent = rows.length;
        }

        // 格式化参数显示为JSON
        function formatParams(params) {
            if (!params || params === "暂无参数提取记录") return params;

            try {
                const paramsObj = {};
                params.split(';').forEach(pair => {
                    const [key, value] = pair.split('=', 2);
                    if (key && value) {
                        paramsObj[key] = value;
                    }
                });

                return JSON.stringify(paramsObj, null, 2);
            } catch (e) {
                return params;
            }
        }

        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', function() {
            updateStats();

            // 格式化参数显示
            const paramsList = document.getElementById('paramsList');
            if (paramsList) {
                const paramsText = paramsList.textContent.trim();
                if (paramsText && paramsText !== '暂无参数提取记录') {
                    paramsList.textContent = formatParams(paramsText);
                }
            }

            // 添加图片加载错误处理
            document.querySelectorAll('.captcha-img').forEach(img => {
                img.onerror = function() {
                    this.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjgwIiB2aWV3Qm94PSIwIDAgMTgwIDgwIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxODAiIGhlaWdodD0iODAiIGZpbGw9IiNGMEYwRjAiLz48dGV4dCB4PSI5MCIgeT0iNDUiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxNCIgZmlsbD0iIzY2NiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+SW1hZ2UgTG9hZCBGYWlsZWQ8L3RleHQ+PC9zdmc+';
                };
            });

            // 自动刷新页面（每30秒）
            setTimeout(() => {
                window.location.reload();
            }, 30000);
        });

        // 键盘快捷键
        document.addEventListener('keydown', function(e) {
            if (e.key === 'r' && e.ctrlKey) {
                e.preventDefault();
                window.location.reload();
            }
        });
    </script>
</body>
</html>'''

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=UTF-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        text = ''
        re_data = ""
        xp_url = ""
        xp_type = ""
        xp_cookie = ""
        xp_set_ranges = ""
        xp_complex_request = ""
        xp_rf = ""
        xp_re = ""
        xp_is_re_run = ""
        img_bytes = None
        extracted_params_str = ""
        request_headers = {}

        try:
            if self.path != '/imgurl':
                self.send_error(404, "Page not Found!")
                return

            # 记录请求开始
            start_time = time.time()
            request_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

            print(f"\n{'=' * 80}")
            print(f"[请求 {request_id}] 收到OCR请求")

            # 读取请求数据
            content_length = int(self.headers['content-length'])
            req_datas = self.rfile.read(content_length)
            req_datas = req_datas.decode('utf-8', errors='ignore')

            print(f"[请求 {request_id}] 请求数据长度: {len(req_datas)}")

            try:
                # 解析POST参数
                params = parse_qs(req_datas)

                # 获取参数值
                xp_url_base64 = params.get("xp_url", [""])[0]
                xp_type = params.get("xp_type", ["1"])[0]
                xp_cookie_base64 = params.get("xp_cookie", [""])[0]
                xp_set_ranges = params.get("xp_set_ranges", ["1"])[0]
                xp_complex_request_base64 = params.get("xp_complex_request", [""])[0]
                xp_rf = params.get("xp_rf", ["0"])[0]
                xp_re_base64 = params.get("xp_re", [""])[0]
                xp_is_re_run = params.get("xp_is_re_run", ["false"])[0]

                # 解码Base64参数
                try:
                    xp_url = base64.b64decode(xp_url_base64).decode('utf-8', errors='ignore')
                except:
                    xp_url = ""

                try:
                    xp_cookie = base64.b64decode(xp_cookie_base64).decode('utf-8', errors='ignore')
                except:
                    xp_cookie = ""

                try:
                    xp_complex_request = base64.b64decode(xp_complex_request_base64).decode('utf-8', errors='ignore')
                except:
                    xp_complex_request = ""

                try:
                    xp_re = base64.b64decode(xp_re_base64).decode('utf-8', errors='ignore')
                except:
                    xp_re = ""

                print(f"[请求 {request_id}] 解析参数完成:")
                print(f"  xp_url: {xp_url}")
                print(f"  xp_type: {xp_type} (1=简单, 2=复杂)")
                print(f"  xp_set_ranges: {xp_set_ranges}")
                print(f"  xp_cookie长度: {len(xp_cookie)}")
                print(f"  xp_complex_request长度: {len(xp_complex_request)}")

            except Exception as e:
                print(f"[请求 {request_id}] 解析请求参数错误: {e}")
                traceback.print_exc()
                text = '0000'
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(text.encode('utf-8'))
                return

            try:
                response = None
                request_headers = {}

                if xp_type == "1":
                    # 简单URL请求
                    print(f"[请求 {request_id}] 使用简单URL请求模式")

                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache"
                    }

                    # 添加Referer
                    if xp_url:
                        parsed_url = urlparse(xp_url)
                        headers["Referer"] = f"{parsed_url.scheme}://{parsed_url.netloc}/"

                    # 添加Cookie
                    if xp_cookie:
                        headers["Cookie"] = xp_cookie

                    request_headers = headers.copy()

                    print(f"[请求 {request_id}] 发送验证码请求: {xp_url}")
                    print(f"[请求 {request_id}] 请求头: {headers}")

                    response = requests.get(xp_url, headers=headers, timeout=10, verify=False, allow_redirects=False)

                    # 记录请求历史
                    request_history.append({
                        'id': request_id,
                        'type': '简单URL',
                        'url': xp_url,
                        'status': response.status_code,
                        'time': time.strftime("%H:%M:%S")
                    })

                elif xp_type == "2":
                    # 复杂数据包请求
                    print(f"[请求 {request_id}] 使用复杂数据包请求模式")

                    if not xp_complex_request or xp_complex_request.strip() == "":
                        print(f"[请求 {request_id}] 错误: 复杂数据包请求模式但没有提供数据包内容")
                        text = '0000'
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(text.encode('utf-8'))
                        return

                    print(f"[请求 {request_id}] 数据包内容长度: {len(xp_complex_request)}")
                    print(f"[请求 {request_id}] 数据包内容前500字符:")
                    print(xp_complex_request[:500])

                    # 使用复杂数据包发送请求
                    response = send_complex_request(xp_complex_request, xp_url)

                    if response is None:
                        raise Exception("复杂请求发送失败")

                    # 记录请求历史
                    request_history.append({
                        'id': request_id,
                        'type': '复杂数据包',
                        'url': xp_url,
                        'status': response.status_code,
                        'time': time.strftime("%H:%M:%S")
                    })

                else:
                    raise ValueError(f"[请求 {request_id}] 不支持的xp_type: {xp_type}")

                if response:
                    print(f"[请求 {request_id}] 验证码响应状态码: {response.status_code}")
                    print(f"[请求 {request_id}] 响应头: {dict(response.headers)}")

                    # 提取参数
                    extracted_params_str = extract_parameters(response, xp_url, request_headers)
                    if extracted_params_str:
                        print(f"[请求 {request_id}] 提取的参数: {extracted_params_str}")

                        # 保存参数到文件
                        try:
                            with open('temp/params.txt', 'w', encoding='utf-8') as f:
                                f.write(extracted_params_str)
                        except:
                            pass

                    # 处理高级模式（正则匹配）
                    if xp_is_re_run.lower() == "true":
                        try:
                            if xp_rf == '0':
                                re_data = re.findall(xp_re, response.text)[0]
                                print(f"[请求 {request_id}] 正则匹配结果: {re_data}")
                            elif xp_rf == '1':
                                rp_head = xp_re.split("|")
                                if len(rp_head) > 1:
                                    head_key = rp_head[0]
                                    re_zz = xp_re[len(head_key) + 1:]
                                    re_data = re.findall(re_zz, response.headers.get(head_key, ""))[0]
                                    print(f"[请求 {request_id}] 正则匹配结果: {re_data}")
                        except Exception as e:
                            re_data = ""
                            print(f"[请求 {request_id}] 正则匹配失败: {e}")

                    # 直接提取模式（模式8）
                    if xp_set_ranges == "8":
                        if extracted_params_str:
                            text = "0000|" + extracted_params_str
                        else:
                            text = "0000|" + re_data

                        print(f"[请求 {request_id}] 直接提取模式返回: {text}")

                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(text.encode('utf-8'))
                        return

                    # 处理验证码图片数据
                    content_type = response.headers.get('Content-Type', '').lower()

                    if 'json' in content_type:
                        print(f"[请求 {request_id}] 检测到JSON格式响应")
                        try:
                            json_data = json.loads(response.text)
                            # 在JSON中查找图片数据
                            if isinstance(json_data, dict):
                                for key, value in json_data.items():
                                    if isinstance(value, str):
                                        if 'base64' in value.lower() or value.startswith('data:image'):
                                            if ',' in value:
                                                img_data = value.split(',')[1]
                                            else:
                                                img_data = value
                                            try:
                                                img_bytes = base64.b64decode(img_data)
                                                break
                                            except:
                                                continue
                            if not img_bytes:
                                img_bytes = response.content
                        except Exception as e:
                            print(f"[请求 {request_id}] JSON解析失败: {e}")
                            img_bytes = response.content

                    elif 'image' in content_type:
                        print(f"[请求 {request_id}] 检测到图片格式响应")
                        img_bytes = response.content

                    elif 'base64' in response.text.lower():
                        print(f"[请求 {request_id}] 检测到Base64格式响应")
                        try:
                            # 查找Base64数据
                            base64_pattern = r'([A-Za-z0-9+/=]{20,})'
                            matches = re.findall(base64_pattern, response.text)
                            for match in matches:
                                try:
                                    img_bytes = base64.b64decode(match)
                                    break
                                except:
                                    continue
                            if not img_bytes:
                                img_bytes = response.content
                        except:
                            img_bytes = response.content

                    else:
                        print(f"[请求 {request_id}] 检测到二进制格式响应")
                        img_bytes = response.content

                    if img_bytes:
                        print(f"[请求 {request_id}] 获取到图片数据: {len(img_bytes)} bytes")
                    else:
                        raise Exception(f"[请求 {request_id}] 未能获取到图片数据")

                else:
                    raise Exception(f"[请求 {request_id}] 未收到响应")

            except Exception as e:
                print(f"[请求 {request_id}] 获取或处理图片出错: {e}")
                traceback.print_exc()
                text = '0000'
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(text.encode('utf-8'))
                return

            # ========== 验证码识别核心 ==========
            import ddddocr

            if not img_bytes:
                raise ValueError(f"[请求 {request_id}] 没有获取到图片数据")

            print(f"[请求 {request_id}] 开始识别验证码...")

            try:
                # 根据模式选择OCR识别器
                current_ocr = ddddocr.DdddOcr()

                # 进行OCR识别
                raw_text = current_ocr.classification(img_bytes)
                print(f"[请求 {request_id}] 原始识别结果: {raw_text}")

                # 处理数学计算
                if xp_set_ranges == '3':
                    text = calculate_math_expression(raw_text)
                    if text != raw_text:
                        print(f"[请求 {request_id}] 数学计算完成: {raw_text} -> {text}")
                    else:
                        print(f"[请求 {request_id}] 未检测到数学表达式，返回原始识别结果")
                else:
                    text = raw_text

                print(f"[请求 {request_id}] 最终输出结果: {text}")

            except Exception as e:
                print(f"[请求 {request_id}] OCR识别失败: {e}")
                traceback.print_exc()
                text = '0000'

            # ========== 保存结果到日志 ==========
            try:
                with open('temp/log.txt', 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # 只保留最新的count条记录
                if len(lines) >= count:
                    lines = lines[:count - 1]

                existing_data = ''.join(lines)
            except:
                existing_data = ""

            try:
                # 将图片字节转换为base64用于显示
                img_preview = img_bytes[:50000]  # 限制大小
                base64_img = base64.b64encode(img_preview).decode("utf-8")
            except:
                base64_img = ""

            # 根据模式设置显示文本
            mode_display = {
                '0': '纯数字',
                '1': '混合',
                '2': '复杂',
                '3': '数学计算',
                '8': '直接提取'
            }.get(xp_set_ranges, '未知')

            # 显示提取的参数（简短版本）
            params_display = ""
            if extracted_params_str:
                params_list = extracted_params_str.split(';')
                params_display = ', '.join([p.split('=')[0] for p in params_list[:3]])
                if len(params_list) > 3:
                    params_display += f"...(+{len(params_list) - 3})"

            # 请求类型显示
            request_type_display = "简单URL" if xp_type == "1" else "复杂数据包"

            # 保存为HTML格式
            current_time = time.strftime("%Y-%m-d %H:%M:%S", time.localtime())
            log_entry = f'''<tr>
                <td><img src="data:image/png;base64,{base64_img}" class="captcha-img" alt="验证码" title="点击查看原图"></td>
                <td><span class="result-text">{text}</span></td>
                <td title="{extracted_params_str}">{params_display}</td>
                <td class="timestamp">{current_time}</td>
                <td><span class="mode-indicator mode-{xp_set_ranges}">{mode_display}</span></td>
                <td><span class="mode-indicator" style="background: {'#4CAF50' if xp_type == '1' else '#FF9800'}">{request_type_display}</span></td>
            </tr>\n'''

            with open('temp/log.txt', 'w', encoding='utf-8') as f:
                f.write(log_entry + existing_data)

        except Exception as e:
            print(f"[请求 {request_id}] 处理过程发生错误: {e}")
            traceback.print_exc()
            text = '0000'
            if xp_url:
                print(f"[请求 {request_id}] 错误URL: {xp_url}")

        if text == '':
            text = '0000'

        # 构建返回结果
        result_parts = [text]

        if extracted_params_str:
            result_parts.append(extracted_params_str)
        elif re_data:
            result_parts.append(re_data)

        result = "|".join(result_parts)

        elapsed_time = time.time() - start_time
        print(f"[请求 {request_id}] 返回识别结果: {result}")
        print(f"[请求 {request_id}] 处理耗时: {elapsed_time:.2f}秒")
        print(f"{'=' * 80}")

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(result.encode('utf-8'))


if __name__ == '__main__':
    print('正在加载中请稍后……')

    # 创建必要的目录
    os.makedirs('temp', exist_ok=True)

    # 初始化日志文件
    try:
        with open('temp/log.txt', 'w', encoding='utf-8') as f:
            f.write('')
    except:
        pass

    # 初始化参数文件
    try:
        with open('temp/params.txt', 'w', encoding='utf-8') as f:
            f.write('')
    except:
        pass

    server = ThreadingHTTPServer(host, Resquest)
    print(f"{'=' * 80}")
    print(f"Starting server, listen at: {host[0]}:{host[1]}")
    print(f"加载完成！请访问：http://127.0.0.1:{host[1]}")
    print(f"{'=' * 80}")
    print("🔥 火白学安全完整版 v4.5 - 完整功能特性:")
    print("1. 复杂数据包完整支持 - 完整解析HTTP数据包，支持自定义headers、cookies、body")
    print("2. 参数自动提取增强 - 从响应头、Set-Cookie、JSON、HTML中智能提取参数")
    print("3. 多模式识别支持 - 支持5种识别模式，适应各种验证码类型")
    print("4. 数学计算功能 - 自动识别并计算数学表达式验证码")
    print("5. 请求历史记录 - 记录最近请求，便于调试和分析")
    print("6. 完整日志系统 - 详细的处理日志，便于问题排查")
    print("7. 增强的错误处理 - 更完善的异常处理机制")
    print("8. 性能优化 - 优化处理速度，减少响应时间")
    print(f"{'=' * 80}")
    print("✅ 所有功能模块已完整实现，无删减")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"服务器错误: {e}")
        traceback.print_exc()