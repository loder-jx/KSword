"""Build gate for the C command catalog consumed by the hvm_ctl probe CLI.

hvm_ctl 是功能测试探针，不是发布物：主程序既不编译这份目录，也不再把它的
命令文案带进语言包。因此这道门只核对目录本身的自洽性（命令名唯一、每条命令
都有派发分支），不再断言 GUI 语言包里存在对应词条——那个断言的前提是目录被
主程序消费，而那条依赖已经摘掉了。
"""
import json
from pathlib import Path
import re


def main():
    here = Path(__file__).resolve().parent
    source = (here / "HvmCommandCatalog.c").read_text(encoding="utf-8-sig")
    catalog = source.split("g_commands[] = {", 1)[1].split("\n};", 1)[0]
    literal = r'"(?:\\.|[^"\\])*"'
    records = re.findall(r"^\s*\{\s*(" + literal + r"),\s*(" + literal + r"),\s*(" +
                         literal + r"),\s*(" + literal + r"),\s*(Hvm\w+),", catalog, re.M)
    assert records, "No command definitions"
    names = [json.loads(r[0]) for r in records]
    assert len(set(names)) == len(names), "Duplicate command name"
    strings = {json.loads(s) for r in records for s in r[1:4]}
    strings.update(json.loads(s) for s in re.findall(r"\{\s*(" + literal + r"),\s*Hvm\w+,", catalog))
    engine = (here / "HvmCommandEngine.c").read_text(encoding="utf-8-sig")
    handlers = set(re.findall(r"case (Hvm\w+):", engine))
    handlers.update(re.findall(r"spec->handler == (Hvm\w+)", engine))
    assert not ({r[4] for r in records} - handlers), "Command has no dispatch handler"
    print(f"HVM_CATALOG_AUDIT=PASS commands={len(records)} texts={len(strings)}")


if __name__ == "__main__":
    main()
