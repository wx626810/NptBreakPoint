# -*- coding: utf-8 -*-
"""
npobf_gen.py — NpHvCtl 字符串混淆生成器（幂等，可重复运行）

原理：C/C++ 字符串字面量是静态存储期常量，必然落盘（.rdata），
任何"宏包装字符串"（如 OBF("...")）都无法避免字面量副本进产物。
因此这里把字符串转成"密文字节数组初始化器"（非 const，进 .data，
防优化器常量折叠），运行时由 NpDec() 解密到 g_decBuf。明文不落盘。

用法：
    1) 修改 NpHvCtl.cpp 中的字符串（用普通字符串字面量写即可）
    2) python npobf_gen.py
    3) g++ -O2 -s -std=c++17 -mwindows -I../NptHook/include NpHvCtl.cpp -o NpHvCtl.exe
    4) 用 python -c "data=open('NpHvCtl.exe','rb').read(); print(data.find(b'特征串'))"
       验证产物中无明文特征

幂等性：脚本会先把现有 NpDec(id) 引用还原为明文，再统一收集重新编号，
因此无论源码当前是明文形式还是 NpDec 形式，结果一致。
"""
import re
import sys

SRC = 'NpHvCtl.cpp'
KEY = 0x5A

API_FUNCS = ('printf', 'CreateFileA', 'LoadLibraryA',
             'GetProcAddress', 'strncpy_s')


def c_escape(raw: bytes) -> str:
    """bytes -> C 字符串字面量内容（含转义，不含引号）。"""
    out = []
    for b in raw:
        if b == 0x0A:
            out.append('\\n')
        elif b == 0x09:
            out.append('\\t')
        elif b == 0x0D:
            out.append('\\r')
        elif b == 0x5C:
            out.append('\\\\')
        elif b == 0x22:
            out.append('\\"')
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append('\\x%02X' % b)
    return ''.join(out)


def c_unescape(s: str) -> bytes:
    """C 字符串字面量内容 -> bytes。"""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            c = s[i + 1]
            if c == 'n':
                out.append(0x0A); i += 2
            elif c == 't':
                out.append(0x09); i += 2
            elif c == 'r':
                out.append(0x0D); i += 2
            elif c == '\\':
                out.append(0x5C); i += 2
            elif c == '"':
                out.append(0x22); i += 2
            elif c == '0':
                out.append(0x00); i += 2
            elif c == 'x':
                out.append(int(s[i + 2:i + 4], 16)); i += 4
            else:
                out.append(ord(c)); i += 2
        else:
            out.extend(s[i].encode('utf-8')); i += 1
    return bytes(out)


def parse_old_table(src: str):
    """从当前源码解析旧表（密文数组 + 长度），返回还原后的字符串列表。"""
    m = re.search(r'static unsigned char g_obs\[(\d+)\]\[(\d+)\] = \{(.*?)\n\};',
                  src, flags=re.S)
    if not m:
        return None
    count, width = int(m.group(1)), int(m.group(2))
    lens = re.search(r'static const int g_obs_len\[\] = \{(.*?)\};', src, flags=re.S)
    if not lens:
        return None
    lengths = [int(x) for x in lens.group(1).split(',')]
    rows = re.findall(r'\{([^}]*)\}', m.group(3))
    assert len(rows) == count, 'table rows mismatch'
    old = []
    for row, ln in zip(rows, lengths):
        bs = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', row))
        old.append(bytes(b ^ KEY for b in bs[:ln]))
    return old


def main():
    src = open(SRC, encoding='utf-8').read()

    # 1) 若存在旧表：还原 NpDec(id) -> "明文"，并删除表块
    old = parse_old_table(src)
    if old is not None:
        def rev(m):
            idx = int(m.group(1))
            if 0 <= idx < len(old):
                return '"' + c_escape(old[idx]) + '"'
            raise SystemExit(f'NpDec({idx}) out of old table range')
        src, n = re.subn(r'NpDec\((\d+)\)', rev, src)
        print(f'[1] restored {n} NpDec refs to plaintext')
        m = re.search(r'\n// 字符串混淆表.*?\n\}\n', src, flags=re.S)
        if m:
            src = src[:m.start()] + '\n' + src[m.end():]
    else:
        print('[1] no old table found (first run)')

    # 2) 收集所有 API 调用中的字符串字面量
    table = []
    pat = re.compile(
        r'((?:%s)\([^"]*)"((?:[^"\\]|\\.)*)"' % '|'.join(API_FUNCS))

    def repl(m):
        pre, lit = m.group(1), m.group(2)
        raw = c_unescape(lit)
        if raw not in table:
            table.append(raw)
        return f'{pre}NpDec({table.index(raw)})'

    src2, n = pat.subn(repl, src)
    print(f'[2] replaced {n} literals, table size = {len(table)}')

    # 3) 生成新表块并插入
    width = max((len(r) for r in table), default=1)
    rows = []
    for raw in table:
        enc = bytes(b ^ KEY for b in raw)
        rows.append('    {' + ','.join('0x%02X' % b for b in enc)
                    + '},   // len=%d' % len(raw))
    block = (
        '\n// 字符串混淆表（脚本生成：npobf_gen.py，勿手改）：密文存 .data\n'
        '// （非 const，防优化器折叠），运行时 NpDec 解密到 g_decBuf。\n'
        '// 字符串字面量本身必落盘，故此处只存密文字节数组初始化器。\n'
        f'static unsigned char g_obs[{len(table)}][{width}] = {{\n'
        + '\n'.join(rows) + '\n'
        '};\n'
        f'static const int g_obs_len[] = {{{", ".join(str(len(r)) for r in table)}}};\n'
        'static char g_decBuf[256];\n'
        '__attribute__((noinline))\n'
        'static const char* NpDec(int id)\n'
        '{\n'
        '    for (int i = 0; i < g_obs_len[id]; i++)\n'
        '        g_decBuf[i] = (char)(g_obs[id][i] ^ 0x5A);\n'
        '    g_decBuf[g_obs_len[id]] = 0;\n'
        '    return g_decBuf;\n'
        '}\n'
    )
    anchor = '#include "../NptHook/include/NpIoctl.h"'
    assert anchor in src2, 'anchor missing'
    src2 = src2.replace(anchor, anchor + block)

    open(SRC, 'w', encoding='utf-8', newline='').write(src2)
    print(f'[3] written. strings:')
    for i, r in enumerate(table):
        print(f'   {i}: {r[:60]!r}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
