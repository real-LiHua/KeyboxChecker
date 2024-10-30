# 批量密钥箱检测器

## 要求
Rust (编译时需要)  
Python >= 3.8  
连接国际互联网，网络代理环境变量：`HTTP_PROXY`，`HTTPS_PROXY`，`ALL_PROXY`。（详见：[Requests 官方文档](https://requests.readthedocs.io/projects/cn/zh-cn/latest/user/advanced.html#proxies)）

## 安装
```bash
pip install keyboxchecker
```

## 使用
```bash
用法：keyboxchecker [-h] [-a] [-o OUTPUT] [-p PATH]

选项：
  -h、--help           显示帮助信息并退出
  -a, --aosp           将 AOSP 密钥盒分类为 “Survivor”，默认值为 “False”
  -o OUTPUT, --output OUTPUT
                       结果输出目录，默认为当前目录
  -p PATH, --path PATH 密钥盒所在目录，默认为当前目录
```

## 卸载
```bash
pip uninstall keyboxchecker
```
