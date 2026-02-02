#!/usr/bin/env python3
"""
网站爬虫 - 安全测试专用
"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque, defaultdict
import time
import os
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedWebCrawler:
    def __init__(self, base_url, max_depth=5, max_workers=5, delay=0.2):
        """
        初始化爬虫
        
        Args:
            base_url: 起始URL
            max_depth: 最大爬取深度
            max_workers: 最大线程数
            delay: 请求延迟
        """
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.delay = delay
        
        # 解析基础URL
        parsed_url = urlparse(base_url)
        self.base_domain = parsed_url.netloc
        self.scheme = parsed_url.scheme or 'http'
        
        # 存储结构
        self.visited = set()
        self.discovered_urls = set()
        self.url_data = defaultdict(dict)  # 存储URL额外信息
        self.stats = {
            'start_time': datetime.now().isoformat(),  # 改为字符串格式
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0
        }
        
        # 请求头
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    def normalize_url(self, url):
        """标准化URL"""
        parsed = urlparse(url)
        
        # 如果没有协议，添加协议
        if not parsed.scheme:
            parsed = parsed._replace(scheme=self.scheme)
        
        # 如果没有域名，添加基础域名
        if not parsed.netloc:
            parsed = parsed._replace(netloc=self.base_domain)
        
        # 标准化路径
        path = parsed.path
        if not path:
            path = '/'
        
        # 移除末尾斜杠（除了根路径）
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        
        parsed = parsed._replace(path=path)
        
        # 重建URL
        return urlunparse(parsed)
    
    def fetch_url(self, url, depth):
        """获取URL内容并提取信息"""
        try:
            time.sleep(self.delay)
            self.stats['total_requests'] += 1
            
            # 添加超时和重试
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=15,
                allow_redirects=True,
                verify=False  # 对于靶场环境，关闭SSL验证
            )
            
            self.stats['successful_requests'] += 1
            
            # 存储响应信息
            self.url_data[url] = {
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'depth': depth,
                'timestamp': datetime.now().isoformat()
            }
            
            # 提取链接
            links = self.extract_links(url, response.text)
            
            # 发现更多潜在路径
            potential_paths = self.find_potential_paths(response.text)
            links.update(potential_paths)
            
            return url, links, response.status_code
            
        except requests.exceptions.ConnectionError:
            self.stats['failed_requests'] += 1
            self.url_data[url] = {
                'error': 'Connection refused',
                'depth': depth,
                'timestamp': datetime.now().isoformat()
            }
            print(f"[!] 连接被拒绝: {url}")
            return url, set(), 0
        except requests.exceptions.Timeout:
            self.stats['failed_requests'] += 1
            self.url_data[url] = {
                'error': 'Request timeout',
                'depth': depth,
                'timestamp': datetime.now().isoformat()
            }
            print(f"[!] 请求超时: {url}")
            return url, set(), 0
        except Exception as e:
            self.stats['failed_requests'] += 1
            self.url_data[url] = {
                'error': str(e),
                'depth': depth,
                'timestamp': datetime.now().isoformat()
            }
            print(f"[!] 请求失败 {url}: {e}")
            return url, set(), 0
    
    def extract_links(self, base_url, html_content):
        """从HTML内容中提取链接"""
        links = set()
        
        # 查找href属性
        href_patterns = [
            r'href=["\'](.*?)["\']',
            r'src=["\'](.*?)["\']',
            r'action=["\'](.*?)["\']',
            r'url\(["\']?(.*?)["\']?\)',
            r'<a[^>]*?href=["\'](.*?)["\'][^>]*?>'
        ]
        
        for pattern in href_patterns:
            try:
                found = re.findall(pattern, html_content, re.IGNORECASE)
                for link in found:
                    # 清理链接
                    link = link.strip()
                    if not link:
                        continue
                    
                    # 移除片段和查询参数
                    link = link.split('#')[0].split('?')[0]
                    
                    # 跳过javascript:等特殊协议
                    if link.lower().startswith(('javascript:', 'mailto:', 'tel:')):
                        continue
                    
                    # 转换相对链接为绝对链接
                    if link.startswith('http://') or link.startswith('https://'):
                        absolute_link = link
                    else:
                        absolute_link = urljoin(base_url, link)
                    
                    # 标准化并过滤
                    absolute_link = self.normalize_url(absolute_link)
                    if self.is_valid_link(absolute_link):
                        links.add(absolute_link)
            except Exception as e:
                print(f"[!] 提取链接时出错 (pattern: {pattern}): {e}")
                continue
        
        return links
    
    def find_potential_paths(self, html_content):
        """从JavaScript和注释中发现潜在路径"""
        potential_paths = set()
        
        try:
            # 查找JavaScript中的路径
            js_patterns = [
                r'["\'](/[^"\']+?)["\']',
                r'["\'](\.\.?/[^"\']+?)["\']',
                r'api["\']?\s*:\s*["\']([^"\']+?)["\']',
                r'endpoint["\']?\s*:\s*["\']([^"\']+?)["\']',
                r'["\'](/(?:api|admin|dashboard|login|register|panel)[^"\']*?)["\']'
            ]
            
            for pattern in js_patterns:
                found = re.findall(pattern, html_content, re.IGNORECASE)
                for path in found:
                    full_url = self.normalize_url(self.base_url + path)
                    if self.is_valid_link(full_url):
                        potential_paths.add(full_url)
            
            # 查找HTML注释中的路径
            comment_pattern = r'<!--.*?-->'
            comments = re.findall(comment_pattern, html_content, re.DOTALL)
            
            for comment in comments:
                # 在注释中查找路径
                paths_in_comment = re.findall(r'(/[a-zA-Z0-9_\-\./]+)', comment)
                for path in paths_in_comment:
                    full_url = self.normalize_url(self.base_url + path)
                    if self.is_valid_link(full_url):
                        potential_paths.add(full_url)
                        
        except Exception as e:
            print(f"[!] 查找潜在路径时出错: {e}")
        
        return potential_paths
    
    def is_valid_link(self, url):
        """检查链接是否有效"""
        try:
            parsed = urlparse(url)
            
            # 检查域名
            if parsed.netloc and parsed.netloc != self.base_domain:
                return False
            
            # 过滤常见静态文件和媒体文件（但可以调整）
            invalid_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv',
                '.woff', '.woff2', '.ttf', '.eot',
                '.zip', '.rar', '.tar', '.gz', '.7z',
                # 保留CSS和JS，因为其中可能包含路径信息
                # '.css', '.js'
            ]
            
            path_lower = parsed.path.lower()
            for ext in invalid_extensions:
                if path_lower.endswith(ext):
                    return False
            
            return True
        except:
            return False
    
    def crawl(self):
        """开始爬取"""
        print(f"[*] 开始爬取: {self.base_url}")
        print(f"[*] 最大深度: {self.max_depth}")
        print(f"[*] 线程数: {self.max_workers}")
        print("-" * 60)
        
        # 首先尝试访问根路径
        initial_url = self.base_url
        self.visited.add(initial_url)
        print(f"[*] 尝试访问初始URL: {initial_url}")
        
        try:
            # 使用单线程测试连接
            response = requests.get(initial_url, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200:
                print(f"[+] 初始连接成功: HTTP {response.status_code}")
                print(f"[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
                print(f"[+] Content-Length: {len(response.content)} bytes")
                
                # 提取初始链接
                initial_links = self.extract_links(initial_url, response.text)
                initial_links.update(self.find_potential_paths(response.text))
                
                print(f"[+] 从初始页面发现 {len(initial_links)} 个链接")
                
                # 存储初始数据
                self.url_data[initial_url] = {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'depth': 0,
                    'timestamp': datetime.now().isoformat()
                }
                self.discovered_urls.add(initial_url)
                self.stats['successful_requests'] += 1
                
                # 准备队列
                queue = deque()
                for link in initial_links:
                    if link not in self.visited:
                        queue.append((link, 1))
                
                # 多线程爬取
                self._threaded_crawl(queue)
                
            else:
                print(f"[!] 初始连接返回 HTTP {response.status_code}")
                self.url_data[initial_url] = {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'depth': 0,
                    'timestamp': datetime.now().isoformat()
                }
                self.discovered_urls.add(initial_url)
                self.stats['successful_requests'] += 1
                
        except requests.exceptions.ConnectionError:
            print(f"[!] 无法连接到 {initial_url}")
            print("[!] 请检查:")
            print("    1. 目标IP/域名是否正确")
            print("    2. 目标服务是否正在运行")
            print("    3. 防火墙设置")
            return
        except Exception as e:
            print(f"[!] 初始连接出错: {e}")
            return
        
        # 显示结果
        self.display_results()
    
    def _threaded_crawl(self, queue):
        """多线程爬取"""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            while queue or futures:
                # 提交新任务
                while queue and len(futures) < self.max_workers * 2:
                    url, depth = queue.popleft()
                    
                    if url not in self.visited and depth <= self.max_depth:
                        self.visited.add(url)
                        future = executor.submit(self.fetch_url, url, depth)
                        futures[future] = (url, depth)
                
                # 处理完成的任务
                if futures:
                    done_futures = list(futures.keys())
                    for future in done_futures:
                        if future.done():
                            url, depth = futures.pop(future)
                            try:
                                source_url, links, status_code = future.result()
                                
                                self.discovered_urls.add(source_url)
                                self.stats['total_requests'] += 1
                                
                                if status_code == 200:
                                    print(f"[+] 深度{depth} [{status_code}]: {source_url}")
                                    
                                    # 如果不是最深层，添加新链接到队列
                                    if depth < self.max_depth:
                                        for link in links:
                                            if link not in self.visited:
                                                queue.append((link, depth + 1))
                                elif status_code > 0:  # 其他HTTP状态码
                                    print(f"[!] 深度{depth} [{status_code}]: {source_url}")
                                    
                            except Exception as e:
                                print(f"[!] 处理 {url} 时出错: {e}")
    
    def display_results(self):
        """显示爬取结果"""
        end_time = datetime.now()
        start_time = datetime.fromisoformat(self.stats['start_time'])
        elapsed = end_time - start_time
        
        print("\n" + "="*60)
        print("[*] 爬取完成!")
        print(f"[*] 耗时: {elapsed}")
        print(f"[*] 总请求数: {self.stats['total_requests']}")
        print(f"[*] 成功请求: {self.stats['successful_requests']}")
        print(f"[*] 失败请求: {self.stats['failed_requests']}")
        print(f"[*] 发现URL总数: {len(self.discovered_urls)}")
        print("-" * 60)
        
        # 按状态码分类
        status_counts = defaultdict(int)
        for url, data in self.url_data.items():
            if 'status_code' in data:
                status_counts[data['status_code']] += 1
        
        if status_counts:
            print("[*] HTTP状态码统计:")
            for status, count in sorted(status_counts.items()):
                print(f"    {status}: {count}")
        else:
            print("[*] 没有获取到有效的HTTP响应")
        
        print("-" * 60)
        
        # 显示发现的URL
        if len(self.discovered_urls) > 1:
            print("[*] 发现的可访问URL:")
            
            # 按路径分类
            paths_by_type = defaultdict(list)
            for url in self.discovered_urls:
                parsed = urlparse(url)
                path = parsed.path
                
                if '/admin' in path.lower():
                    paths_by_type['管理后台'].append(url)
                elif '/api' in path.lower():
                    paths_by_type['API接口'].append(url)
                elif '/login' in path.lower() or '/auth' in path.lower():
                    paths_by_type['登录页面'].append(url)
                elif path.endswith('.php'):
                    paths_by_type['PHP文件'].append(url)
                elif path.endswith('.html') or path.endswith('.htm'):
                    paths_by_type['HTML页面'].append(url)
                elif path.endswith('.js'):
                    paths_by_type['JS文件'].append(url)
                elif path.endswith('.css'):
                    paths_by_type['CSS文件'].append(url)
                else:
                    paths_by_type['其他'].append(url)
            
            for type_name, urls in paths_by_type.items():
                if urls:
                    print(f"\n  [+] {type_name} ({len(urls)}):")
                    for url in sorted(urls)[:20]:  # 只显示前20个
                        data = self.url_data.get(url, {})
                        status = data.get('status_code', 'N/A')
                        print(f"      [{status}] {url}")
                    if len(urls) > 20:
                        print(f"      ... 还有 {len(urls)-20} 个未显示")
        
        # 保存结果
        self.save_results()
    
    def save_results(self):
        """保存多种格式的结果"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"crawl_results_{self.base_domain}_{timestamp}"
        
        try:
            # 保存为TXT
            txt_file = f"{base_filename}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"爬取目标: {self.base_url}\n")
                f.write(f"开始时间: {self.stats['start_time']}\n")
                f.write(f"URL总数: {len(self.discovered_urls)}\n")
                f.write(f"成功请求: {self.stats['successful_requests']}\n")
                f.write(f"失败请求: {self.stats['failed_requests']}\n")
                f.write("="*60 + "\n\n")
                
                # 按状态码排序
                urls_by_status = defaultdict(list)
                for url in self.discovered_urls:
                    data = self.url_data.get(url, {})
                    status = data.get('status_code', 0)
                    urls_by_status[status].append(url)
                
                for status in sorted(urls_by_status.keys()):
                    f.write(f"\n状态码 {status}:\n")
                    for url in sorted(urls_by_status[status]):
                        f.write(f"  {url}\n")
            
            # 保存为JSON（包含更多信息）
            json_file = f"{base_filename}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                results = {
                    'target': self.base_url,
                    'stats': self.stats,
                    'urls': []
                }
                
                for url in sorted(self.discovered_urls):
                    data = self.url_data.get(url, {}).copy()
                    # 确保所有数据都是JSON可序列化的
                    for key, value in data.items():
                        if isinstance(value, datetime):
                            data[key] = value.isoformat()
                    data['url'] = url
                    results['urls'].append(data)
                
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            # 保存为简单列表（用于其他工具）
            list_file = f"{base_filename}_urls.txt"
            with open(list_file, 'w', encoding='utf-8') as f:
                for url in sorted(self.discovered_urls):
                    f.write(f"{url}\n")
            
            print(f"\n[*] 结果已保存到文件:")
            print(f"    TXT格式: {txt_file}")
            print(f"    JSON格式: {json_file}")
            print(f"    URL列表: {list_file}")
            
        except Exception as e:
            print(f"[!] 保存结果时出错: {e}")
            import traceback
            traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description='网站爬虫 - 靶场专用')
    parser.add_argument('url', help='目标URL (例如: http://example.com)')
    parser.add_argument('-d', '--depth', type=int, default=3, help='爬取深度 (默认: 3)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='线程数 (默认: 5)')
    parser.add_argument('-w', '--delay', type=float, default=0.2, help='请求延迟(秒) (默认: 0.2)')
    parser.add_argument('--no-verify', action='store_true', help='跳过SSL证书验证')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("            网站爬虫 - 靶场专用")
    print("=" * 60)
    
    # 禁用SSL警告（如果是HTTPS）
    if args.no_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 创建爬虫实例
    crawler = AdvancedWebCrawler(
        base_url=args.url,
        max_depth=args.depth,
        max_workers=args.threads,
        delay=args.delay
    )
    
    try:
        crawler.crawl()
    except KeyboardInterrupt:
        print("\n[!] 用户中断爬取")
        crawler.display_results()
    except Exception as e:
        print(f"\n[!] 爬取过程中出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
