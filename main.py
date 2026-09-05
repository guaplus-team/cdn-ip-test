import ssl
import socket
import ipaddress
import concurrent.futures

# 解析单行 IP、CIDR 或范围
def parse_ip_line(line):
    line = line.strip()
    if not line:
        return []
    
    ips = []
    try:
        if '-' in line:
            # 解析范围，例如：1.1.1.1-1.1.1.255
            start_str, end_str = line.split('-', 1)
            start_ip = int(ipaddress.IPv4Address(start_str.strip()))
            end_ip = int(ipaddress.IPv4Address(end_str.strip()))
            for ip_int in range(start_ip, end_ip + 1):
                ips.append(str(ipaddress.IPv4Address(ip_int)))
        elif '/' in line:
            # 解析 CIDR，例如：1.1.1.0/24
            network = ipaddress.ip_network(line, strict=False)
            for ip in network:
                ips.append(str(ip))
        else:
            # 单个 IP
            ips.append(str(ipaddress.IPv4Address(line)))
    except ValueError as e:
        print(f"[-] 忽略无效格式的 IP/IP段: {line} ({e})")
        
    return ips

# 单个 IP 的核心检测逻辑
def check_ip(ip, domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(5)
        conn.connect((ip, 443))

        request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {domain}\r\nConnection: close\r\n\r\n"
        conn.send(request.encode())

        response = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            response += data
        conn.close()

        header_text = response.decode(errors='ignore')
        if "HTTP/1.1 200 OK" in header_text:
            print(f"[✔] {ip} 有效")
            return ip
        else:
            print(f"[×] {ip} 无效")
            return None
            
    except Exception as e:
        # 在多线程下，隐藏连接失败的具体报错信息，防止刷屏
        print(f"[!] {ip} 连接失败: {e}")
        return None

if __name__ == "__main__":
    # 配置多线程并发数，可根据带宽和系统限制自行调节
    MAX_WORKERS = 50

    # 1. 读取域名
    try:
        with open('./config.txt', 'r') as f:
            domain = f.read().strip()
    except FileNotFoundError:
        print("[-] 未找到 config.txt，请检查文件是否存在。")
        exit(1)

    # 2. 读取并解析 IP 列表
    all_ips = []
    try:
        with open('./source.txt', 'r') as f:
            for line in f:
                all_ips.extend(parse_ip_line(line))
    except FileNotFoundError:
        print("[-] 未找到 source.txt，请检查文件是否存在。")
        exit(1)

    # 列表去重并保持原始顺序
    all_ips = list(dict.fromkeys(all_ips))
    print(f"[*] 共解析出 {len(all_ips)} 个待测 IP，开始以 {MAX_WORKERS} 线程并发检测...")

    # 3. 多线程并发检测
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 将任务提交给线程池
        future_to_ip = {executor.submit(check_ip, ip, domain): ip for ip in all_ips}
        
        # 收集结果
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                results.append(result)

    # 4. 保存有效结果
    with open('./results.txt', 'w') as f:
        for ip in results:
            f.write(ip + '\n')

    print(f"\n✅ 检测完成，共发现 {len(results)} 个可用 IP。结果已写入 results.txt")