#!/usr/bin/python
# -*- coding:utf-8 -*-

import os
import yaml
import pycurl
import io
import json
import pandas as pd
import traceback
from urllib.parse import quote_plus
from sqlalchemy import create_engine, text
from tkinter import filedialog, Tk, Text, Button, Frame, Label, Entry, StringVar, messagebox


class AuditManager:
    def __init__(self):
        self.config_dir = './config'
        self.scanners_yaml_path = os.path.join(self.config_dir, 'config.yaml')
        self.scanners_config = {}
        self.db_config = {}
        self._load_config()

    def _load_config(self):
        try:
            if not os.path.exists(self.scanners_yaml_path):
                # 如果配置文件不存在，创建一个空的配置结构防止报错，或者打印提示
                print(f"警告: 配置文件不存在 {self.scanners_yaml_path}")
                return

            with open(self.scanners_yaml_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                self.scanners_config = config.get('scanners', {})
                self.db_config = config.get('database', {})
        except Exception as e:
            print(f"配置加载失败: {e}")

    def _api_call(self, url):
        """API请求封装"""
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.SSL_VERIFYPEER, False)
        curl.setopt(pycurl.SSL_VERIFYHOST, False)
        curl.setopt(pycurl.TIMEOUT, 60)  # 获取报告可能很慢，设置60秒

        buf = io.BytesIO()
        curl.setopt(pycurl.WRITEDATA, buf)

        try:
            curl.perform()
            http_code = curl.getinfo(pycurl.HTTP_CODE)
            res_content = buf.getvalue().decode('utf-8')
            curl.close()

            if http_code != 200:
                print(f"HTTP错误({http_code}) URL: {url}")
                return {"error": f"HTTP_{http_code}", "raw": res_content}

            if not res_content: return {"error": "EMPTY"}
            return json.loads(res_content)
        except Exception as e:
            return {"error": "EXCEPTION", "msg": str(e)}

    def check_task_status(self, scanner, tid):
        """检查任务状态 (4=完成)"""
        auth = self.scanners_config.get(scanner)
        if not auth: return False

        user, pwd = quote_plus(str(auth['username'])), quote_plus(str(auth['password']))
        try:
            tid_clean = str(int(float(tid)))
        except:
            tid_clean = str(tid)

        url = f"https://{scanner}/api/task/status/{tid_clean}?username={user}&password={pwd}&format=json"

        resp = self._api_call(url)
        if "error" in resp: return False

        data = resp.get('data', {})
        status = str(data.get('status', ''))
        print(f"DEBUG: 任务 {tid_clean} 状态码: {status}")
        return status == '4'

    def get_scan_results_map(self, scanner, tid):
        """
        获取结果并构建查找字典。
        返回结构: { 'IP地址': { '端口号': set(['漏洞名1', '漏洞名2']) } }
        """
        auth = self.scanners_config.get(scanner)
        if not auth:
            print(f"❌ 未找到扫描器配置: {scanner}")
            return None
            
        user, pwd = quote_plus(str(auth['username'])), quote_plus(str(auth['password']))
        try:
            tid_clean = str(int(float(tid)))
        except:
            tid_clean = str(tid)

        # 增加 page_size 参数，防止分页导致数据不全
        url = f"https://{scanner}/api/report/task/{tid_clean}?username={user}&password={pwd}&format=json&page_size=2000"

        print(f"DEBUG: 拉取结果 URL: {url}")
        resp = self._api_call(url)

        # 检查基本的错误标志
        if "error" in resp:
            print(f"❌ 获取失败: {resp}")
            return None
            
        # 某些接口返回 ret_code
        if 'ret_code' in resp and str(resp.get('ret_code')) != '0':
             print(f"❌ API返回错误代码: {resp}")
             return None

        data = resp.get('data', {})
        # --- 核心修复：解析 report 层级 ---
        # 兼容处理：尝试从 report 中找 targets (常见) 或 hosts
        report_data = data.get('report', {})
        
        targets = []
        if isinstance(report_data, list):
            targets = report_data
        elif isinstance(report_data, dict):
            targets = report_data.get('targets') or report_data.get('hosts') or []

        if not targets:
            # 尝试直接从 data 获取 (兼容旧版)
            targets = data.get('hosts') or data.get('targets') or []

        print(f"DEBUG: 提取到 {len(targets)} 个目标主机记录")

        # 构建查找字典: scan_map[ip][port] = {vulns}
        scan_map = {}

        for target in targets:
            # 提取IP
            ip = str(target.get('ip') or target.get('target') or target.get('url') or '').strip()
            if not ip: continue

            if ip not in scan_map:
                scan_map[ip] = {}

            # 定义添加漏洞的辅助函数
            def add_vuln_to_map(v_port, v_name):
                v_port = str(v_port).strip()
                v_name = str(v_name).strip()
                
                # 规范化端口: 空或None转为"0"
                if not v_port or v_port.lower() == 'none': 
                    v_port = "0"
                
                if not v_name: return

                if v_port not in scan_map[ip]:
                    scan_map[ip][v_port] = set()
                scan_map[ip][v_port].add(v_name)

            # --- 1. 提取直接挂在 target 下的漏洞 (通常是主机漏洞) ---
            vuls = target.get('vulnerabilities') or target.get('vul_list') or []
            for v in vuls:
                port = v.get('port', '')
                name = v.get('vulnerability_name') or v.get('name') or v.get('vul_name', '')
                add_vuln_to_map(port, name)

            # --- 2. 提取挂在 services/ports 下的漏洞 (这是之前可能缺失的部分) ---
            # 许多扫描器将端口漏洞放在 services 列表里
            services = target.get('services') or target.get('ports') or []
            for svc in services:
                # 服务层级的端口
                svc_port = svc.get('port', '')
                
                # 获取该服务下的漏洞列表
                svc_vuls = svc.get('vulnerabilities') or svc.get('vul_list') or []
                
                for v in svc_vuls:
                    # 优先使用漏洞自身的端口字段，如果没有则继承服务的端口
                    v_port = v.get('port')
                    if not v_port:
                        v_port = svc_port
                    
                    name = v.get('vulnerability_name') or v.get('name') or v.get('vul_name', '')
                    add_vuln_to_map(v_port, name)

        return scan_map

    def audit_and_update_db(self, scanner, tid, target_ips):
        """
        执行双层逻辑审计
        1. 查不到端口 -> 端口关闭
        2. 查到端口但查不到漏洞 -> 已整改
        """
        scan_map = self.get_scan_results_map(scanner, tid)

        if scan_map is None:
            return -1  # 失败

        # 检查数据库配置
        if not self.db_config or 'url' not in self.db_config:
            print("❌ 数据库配置缺失")
            return -2

        engine = create_engine(self.db_config['url'])

        ids_port_closed = []  # 待更新为 端口关闭
        ids_rectified = []  # 待更新为 已整改

        try:
            with engine.connect() as conn:
                # 查数据库
                # 使用参数化查询更安全，但这里IN子句需要特殊处理或多次查询
                # 这里保持原逻辑但增加空列表检查
                if not target_ips:
                    print("⚠️ 目标IP列表为空，跳过数据库查询")
                    return 0

                # 简单处理SQL IN注入风险: 确保IP都是安全的字符串
                clean_ips = [x.replace("'", "") for x in target_ips]
                ips_sql = "('" + "','".join(clean_ips) + "')"
                
                query = text(f"SELECT id, ip, port, vulerability_name FROM test WHERE ip IN {ips_sql}")
                db_rows = conn.execute(query).fetchall()

                for row in db_rows:
                    db_ip = str(row.ip).strip()
                    db_port = str(row.port).strip()
                    db_vul = str(row.vulerability_name).strip()
                    
                    # 数据库里的端口如果为空，视作 "0" 处理
                    if not db_port or db_port.lower() == 'none':
                        db_port = "0"

                    # 逻辑开始
                    # 1. 检查 IP 是否存在于扫描结果中
                    if db_ip in scan_map:
                        ip_scan_data = scan_map[db_ip]

                        # 2. 检查 端口 是否存在
                        # 注意：数据库存的端口可能是 "80"，扫描结果可能是 "80" 或 "80/tcp" 等，这里做个简单包含或全等
                        # 为简化，假设都是纯数字或完全一致
                        if db_port in ip_scan_data:
                            # 端口存在，检查漏洞名称
                            port_vulns = ip_scan_data[db_port]

                            if db_vul not in port_vulns:
                                # 端口开着，但没有这个漏洞了 -> 已整改
                                ids_rectified.append(row.id)
                            else:
                                # 端口开着，漏洞也有 -> 未整改 (不做操作)
                                pass
                        else:
                            # 3. IP在，但端口不在结果中 -> 端口关闭
                            ids_port_closed.append(row.id)
                    else:
                        # IP 都不在扫描结果中 (可能是主机不存活)
                        ids_port_closed.append(row.id)

                # 批量回写数据库
                if ids_port_closed:
                    print(f"DEBUG: 更新 {len(ids_port_closed)} 条为 [端口关闭]")
                    update_sql = text("UPDATE test SET zhenggaiqingkuang = '端口关闭' WHERE id IN :ids")
                    conn.execute(update_sql, {"ids": ids_port_closed})

                if ids_rectified:
                    print(f"DEBUG: 更新 {len(ids_rectified)} 条为 [已整改]")
                    update_sql = text("UPDATE test SET zhenggaiqingkuang = '已整改' WHERE id IN :ids")
                    conn.execute(update_sql, {"ids": ids_rectified})

                conn.commit()

        except Exception as e:
            print(f"数据库操作失败: {e}")
            traceback.print_exc()
            return -2

        return len(ids_port_closed) + len(ids_rectified)


def run_audit_process(result_file, log_widget):
    if not result_file: return
    log_widget.delete(1.0, "end")
    manager = AuditManager()
    
    # 检查配置是否加载成功
    if not manager.scanners_config:
        log_widget.insert("end", "⚠️ 配置文件加载失败或为空，请检查 config/config.yaml\n")
        return

    try:
        df = pd.read_excel(result_file).fillna('').astype(str)
        # 优化任务ID清理逻辑
        def clean_tid(x):
            try:
                if not x or x.lower() == 'nan': return ''
                return str(int(float(x)))
            except:
                return str(x)
                
        df['任务ID'] = df['任务ID'].apply(clean_tid)
        
        # 过滤掉无效任务ID
        df_valid = df[df['任务ID'] != '']
        if df_valid.empty:
             log_widget.insert("end", "⚠️ Excel中没有有效任务信息。\n")
             return

        tasks = df_valid.groupby(['扫描器地址', '任务ID'])

        for (scanner, tid), group in tasks:
            log_widget.insert("end", f"\n🔎 审计开始: 扫描器[{scanner}] 任务[{tid}]...\n")
            log_widget.see("end")
            
            # 强制刷新UI
            log_widget.update()

            if not manager.check_task_status(scanner, tid):
                log_widget.insert("end", f" ⏳ 任务未完成或无法连接，跳过。\n")
                continue

            target_ips = group['IP地址'].unique().tolist()
            # 过滤空IP
            target_ips = [ip for ip in target_ips if ip and ip.lower() != 'nan']
            
            count = manager.audit_and_update_db(scanner, tid, target_ips)

            if count < 0:
                log_widget.insert("end", f" ❌ 审计失败 (API错误或数据库错误)\n")
            else:
                log_widget.insert("end", f" ✅ 审计完成! 共更新 {count} 条状态(含端口关闭/已整改)。\n")

    except Exception as e:
        log_widget.insert("end", f"❌ 程序崩溃: {str(e)}\n")
        traceback.print_exc()


def start_gui():
    root = Tk();
    root.title("RSAS 高级审计工具 V7.1 (优化版)");
    root.geometry("700x550")
    path_var = StringVar()
    Frame(root, height=10).pack()
    Label(root, text="选择下发结果 Excel:", font=("微软雅黑", 10)).pack()
    f = Frame(root, padx=20);
    f.pack(fill='x')
    Entry(f, textvariable=path_var).pack(side='left', fill='x', expand=True, padx=5)
    Button(f, text="浏览...", command=lambda: path_var.set(filedialog.askopenfilename())).pack(side='left')
    log_box = Text(root, bg="#263238", fg="#80CBC4", font=("Consolas", 10))
    btn = Button(root, text="开始双层逻辑审计", bg="#00695C", fg="white", height=2,
                 command=lambda: run_audit_process(path_var.get(), log_box))
    btn.pack(pady=20, padx=20, fill='x')
    log_box.pack(padx=20, pady=10, fill='both', expand=True)
    root.mainloop()


if __name__ == "__main__":
    start_gui()
