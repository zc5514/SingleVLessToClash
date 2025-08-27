import base64
import sys
import yaml
import json
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from urllib.parse import urlparse, parse_qs, unquote


def parse_vless_link(vless_link):
    """
    解析VLESS链接
    """
    # 移除前缀
    if vless_link.startswith("vless://"):
        vless_link = vless_link[8:]
    
    # 分离用户信息和服务器信息
    user_info, server_info = vless_link.split("@", 1)
    uuid = user_info
    
    # 分离服务器地址和参数
    if "?" in server_info:
        server_port, params_str = server_info.split("?", 1)
        # 分离锚点(名称)
        if "#" in params_str:
            params_str, name = params_str.split("#", 1)
            name = unquote(name)
        else:
            name = "VLESS Node"
    else:
        if "#" in server_info:
            server_port, name = server_port.split("#", 1)
            name = unquote(name)
            params_str = ""
        else:
            server_port = server_info
            params_str = ""
            name = "VLESS Node"
    
    # 解析服务器地址和端口
    if ":" in server_port:
        server, port = server_port.rsplit(":", 1)
        port = int(port)
    else:
        server = server_port
        port = 443
    
    # 解析参数
    params = parse_qs(params_str)
    
    # 构建配置字典
    config = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "tls": "security" in params and params["security"][0] == "tls",
        "network": params.get("type", ["ws"])[0],
        "udp": True
    }
    
    # 处理ws-opts
    if config["network"] == "ws":
        ws_opts = {}
        if "path" in params:
            path = params["path"][0]
            # 处理早期数据参数
            if "?ed=" in path:
                path, ed = path.split("?ed=", 1)
                ws_opts["max-early-data"] = int(ed)
                ws_opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            
            ws_opts["path"] = unquote(path)
        
        if "host" in params:
            ws_opts["headers"] = {"host": params["host"][0]}
        
        config["ws-opts"] = ws_opts
    
    # 处理TLS选项
    if config["tls"]:
        if "sni" in params:
            config["servername"] = params["sni"][0]
        elif "host" in params:
            config["servername"] = params["host"][0]
        
        if "fp" in params:
            config["client-fingerprint"] = params["fp"][0]
        else:
            config["client-fingerprint"] = "random"
        
        if "alpn" in params:
            alpn = params["alpn"][0]
            config["alpn"] = alpn.split(",")
        
        config["skip-cert-verify"] = False
    
    return config


def convert_vmess_link(vmess_link):
    """
    转换Vmess链接为clash配置
    """
    if vmess_link.startswith("vmess://"):
        vmess_link = vmess_link[8:]
    
    # Base64解码
    try:
        decode_vmess = base64.b64decode(vmess_link).decode('utf-8')
        vmess_data = json.loads(decode_vmess)
    except Exception as e:
        raise Exception(f"无法解析Vmess链接: {str(e)}")
    
    config = {
        "name": vmess_data.get("ps", "Vmess Node"),
        "type": "vmess",
        "server": vmess_data.get("add", ""),
        "port": int(vmess_data.get("port", 0)),
        "uuid": vmess_data.get("id", ""),
        "alterId": int(vmess_data.get("aid", 0)),
        "cipher": vmess_data.get("scy", "auto"),
        "tls": vmess_data.get("tls") == "tls",
        "network": vmess_data.get("net", "tcp"),
        "udp": True
    }
    
    # 处理ws网络
    if config["network"] == "ws":
        ws_opts = {}
        if "path" in vmess_data and vmess_data["path"]:
            ws_opts["path"] = vmess_data["path"]
        if "host" in vmess_data and vmess_data["host"]:
            ws_opts["headers"] = {"host": vmess_data["host"]}
        config["ws-opts"] = ws_opts
    
    return config


def load_template(template_file="template.yaml"):
    """
    加载模板文件
    """
    try:
        with open(template_file, encoding="utf-8") as file:
            return yaml.load(file.read(), Loader=yaml.FullLoader)
    except FileNotFoundError:
        # 如果模板文件不存在，创建一个基础模板
        return {
            "mixed-port": 7890,
            "log-level": "info",
            "proxies": [],
            "proxy-groups": [{
                "name": "PROXY",
                "type": "select",
                "proxies": []
            }],
            "rules": [
                "MATCH,PROXY"
            ]
        }


def save_config(config_data, output_file="SVTC.yaml"):
    """
    保存配置到YAML文件
    """
    with open(output_file, "w", encoding="utf-8") as file:
        yaml.dump(config_data, file, allow_unicode=True, sort_keys=False)


class SVTCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SVTC - Simple Vmess/VLESS to Clash")
        self.root.geometry("800x600")
        
        # 创建界面元素
        self.create_widgets()
        
        # 存储节点配置
        self.proxies = []
    
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # 协议选择
        ttk.Label(main_frame, text="协议类型:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.protocol_var = tk.StringVar(value="vmess")
        protocol_frame = ttk.Frame(main_frame)
        protocol_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Radiobutton(protocol_frame, text="Vmess", variable=self.protocol_var, value="vmess").pack(side=tk.LEFT)
        ttk.Radiobutton(protocol_frame, text="VLESS", variable=self.protocol_var, value="vless").pack(side=tk.LEFT)
        
        # 输入框
        ttk.Label(main_frame, text="节点链接:").grid(row=1, column=0, sticky=(tk.W, tk.N), pady=5)
        self.link_text = scrolledtext.ScrolledText(main_frame, height=10)
        self.link_text.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.rowconfigure(1, weight=1)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        # 添加节点按钮
        self.add_button = ttk.Button(button_frame, text="添加节点", command=self.add_proxy)
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        # 清空按钮
        self.clear_button = ttk.Button(button_frame, text="清空节点", command=self.clear_proxies)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # 生成配置按钮
        self.generate_button = ttk.Button(button_frame, text="生成配置", command=self.generate_config)
        self.generate_button.pack(side=tk.LEFT, padx=5)
        
        # 日志框
        ttk.Label(main_frame, text="日志:").grid(row=3, column=0, sticky=(tk.W, tk.N), pady=5)
        self.log_text = scrolledtext.ScrolledText(main_frame, height=8)
        self.log_text.grid(row=3, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.rowconfigure(3, weight=1)
        
        # 初始化日志
        self.log("SVTC 已启动，支持 Vmess 和 VLESS 协议")
        self.log("请在上方输入框中输入节点链接，每行一个")
    
    def log(self, message):
        """
        添加日志信息
        """
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
    
    def add_proxy(self):
        """
        添加节点配置
        """
        links = self.link_text.get("1.0", tk.END).strip().split("\n")
        added_count = 0
        
        for link in links:
            link = link.strip()
            if not link:
                continue
                
            try:
                if self.protocol_var.get() == "vmess" and link.startswith("vmess://"):
                    proxy = convert_vmess_link(link)
                    self.proxies.append(proxy)
                    self.log(f"已添加 Vmess 节点: {proxy['name']}")
                    added_count += 1
                elif self.protocol_var.get() == "vless" and link.startswith("vless://"):
                    proxy = parse_vless_link(link)
                    self.proxies.append(proxy)
                    self.log(f"已添加 VLESS 节点: {proxy['name']}")
                    added_count += 1
                else:
                    self.log(f"跳过无效链接: {link[:50]}...")
            except Exception as e:
                self.log(f"解析链接失败: {str(e)}")
        
        self.log(f"成功添加 {added_count} 个节点")
        # 清空输入框
        self.link_text.delete("1.0", tk.END)
    
    def clear_proxies(self):
        """
        清空节点列表
        """
        self.proxies = []
        self.log("已清空所有节点")
    
    def generate_config(self):
        """
        生成Clash配置文件
        """
        if not self.proxies:
            messagebox.showwarning("警告", "没有节点可以生成配置")
            return
        
        try:
            # 加载模板
            config = load_template()
            
            # 添加节点
            config["proxies"] = self.proxies
            
            # 更新代理组
            if "proxy-groups" in config and len(config["proxy-groups"]) > 0:
                proxy_names = [proxy["name"] for proxy in self.proxies]
                config["proxy-groups"][0]["proxies"] = proxy_names
            
            # 保存配置
            save_config(config)
            self.log("配置文件已保存为 SVTC.yaml")
            messagebox.showinfo("成功", "配置文件已生成并保存为 SVTC.yaml")
        except Exception as e:
            self.log(f"生成配置失败: {str(e)}")
            messagebox.showerror("错误", f"生成配置失败: {str(e)}")


def main():
    # 命令行模式
    if len(sys.argv) > 1:
        link = sys.argv[1]
        try:
            if link.startswith("vmess://"):
                proxy = convert_vmess_link(link)
            elif link.startswith("vless://"):
                proxy = parse_vless_link(link)
            else:
                print("不支持的协议类型")
                return
            
            # 加载模板
            config = load_template()
            
            # 添加节点
            config["proxies"] = [proxy]
            
            # 更新代理组
            if "proxy-groups" in config and len(config["proxy-groups"]) > 0:
                config["proxy-groups"][0]["proxies"] = [proxy["name"]]
            
            # 保存配置
            save_config(config)
            print("配置文件已保存为 SVTC.yaml")
        except Exception as e:
            print(f"转换失败: {str(e)}")
    else:
        # GUI模式
        root = tk.Tk()
        app = SVTCApp(root)
        root.mainloop()


if __name__ == "__main__":
    main()