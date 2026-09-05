"""驱动重嵌工具：把最新编译的 NpHv.sys 编码进 NpHvCtl/embedded_drivers.h。

为什么必须跑它：NpHvCtl.exe / NpHvCtl-Tauri.exe 都从 embedded_drivers.h 解密落盘
加载驱动，**不读 output\\NpHv.sys**。只重编驱动不重嵌 = 装的还是旧驱动
（历史教训：误判"代码没生效"，实为新 EXE 携带旧驱动）。

编码格式与读取端一致：enc[i] = sys[i] ^ 0x5A ^ (i & 0xFF)（见头文件注释）。
只替换 g_NpHvBytes 段；g_HwRwBytes（BYOVD 漏洞驱动）原样保留。

用法：python tools/embed_drivers.py [驱动sys路径，默认 x64\\Release\\NpHv.sys]
"""
import os, sys, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HDR = os.path.join(ROOT, 'NpHvCtl', 'embedded_drivers.h')
DEFAULT_SYS = os.path.join(ROOT, 'x64', 'Release', 'NpHv.sys')


def encode(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 12):
        chunk = data[off:off + 12]
        hexs = ','.join('0x%02X' % (b ^ 0x5A ^ ((off + i) & 0xFF)) for i, b in enumerate(chunk))
        lines.append(' ' + hexs + ',')
    return '\n'.join(lines) + '\n'


def main():
    sys_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SYS
    if not os.path.isfile(sys_path):
        print(f'[ERROR] 驱动不存在: {sys_path}')
        sys.exit(1)
    data = open(sys_path, 'rb').read()
    if len(data) < 0x400 or data[:2] != b'MZ':
        print(f'[ERROR] {sys_path} 不是合法 PE')
        sys.exit(1)

    src = open(HDR, 'r', encoding='utf-8').read()
    pat = re.compile(
        r'(const unsigned char g_NpHvBytes\[\] = \{\n).*?(\};\nconst unsigned int g_NpHvBytes_len = )\d+(;)',
        re.S)
    if 'g_NpHvBytes[]' not in src:
        print('[ERROR] embedded_drivers.h 中找不到 g_NpHvBytes 段')
        sys.exit(1)
    new = pat.sub(lambda m: m.group(1) + encode(data) + m.group(2) + str(len(data)) + m.group(3), src, count=1)
    with open(HDR, 'w', encoding='utf-8', newline='') as f:
        f.write(new)
    print(f'[OK] {sys_path} ({len(data):,} bytes) -> embedded_drivers.h (g_NpHvBytes 已更新, g_HwRwBytes 保留)')


if __name__ == '__main__':
    main()
