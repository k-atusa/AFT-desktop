# test788 : embed_bin

import sys
import os
import base64
import re

CHUNK_SIZE = 160 # max string len per line

def sanitize_name(filename): # convert filename to funcname
    name = os.path.basename(filename)
    name = os.path.splitext(name)[0]
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def get_chunks(data_bytes): # encode data and split
    b64_str = base64.b64encode(data_bytes).decode('utf-8')
    return [b64_str[i:i+CHUNK_SIZE] for i in range(0, len(b64_str), CHUNK_SIZE)]

def generate_python(files): # python code
    lines = ["import base64", "", "class GetBin:"]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
        
        lines.append(f"    @staticmethod")
        lines.append(f"    def {func_name}():")
        lines.append("        data = (")
        for chunk in chunks:
            lines.append(f"            '{chunk}'")
        lines.append("        )")
        lines.append("        return base64.b64decode(data)")
        lines.append("")
    return "\n".join(lines)

def generate_javascript(files): # javascript code
    lines = ["package GetBin", "", "class GetBin {"]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
            
        lines.append(f"    static {func_name}() {{")
        lines.append("        const parts = [")
        for chunk in chunks:
            lines.append(f"            '{chunk}',")
        lines.append("        ];")
        lines.append("        return Buffer.from(parts.join(''), 'base64');")
        lines.append("    }")
    lines.append("}")
    lines.append("module.exports = GetBin;")
    return "\n".join(lines)

def generate_go(files): # golang code
    lines = [
        "package main", 
        "", 
        "import (", 
        '\t"encoding/base64"', 
        '\t"strings"', 
        ")", 
        "", 
        "type GetBin struct {}", 
        ""
    ]
    for filepath in files:
        # Go는 Public 메서드가 되려면 대문자로 시작해야 함
        func_name = sanitize_name(filepath)
        func_name = func_name[0].upper() + func_name[1:]
        
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())

        lines.append(f"func (g *GetBin) {func_name}() ([]byte, error) {{")
        lines.append("\tparts := []string{")
        for chunk in chunks:
            lines.append(f'\t\t"{chunk}",')
        lines.append("\t}")
        lines.append('\treturn base64.StdEncoding.DecodeString(strings.Join(parts, ""))')
        lines.append("}")
        lines.append("")
    return "\n".join(lines)

def generate_java(files): # java code
    lines = [
        "import java.util.Base64;", 
        "", 
        "public class GetBin {",
    ]
    for filepath in files:
        func_name = sanitize_name(filepath)
        with open(filepath, 'rb') as f:
            chunks = get_chunks(f.read())
            
        lines.append(f"    public static byte[] {func_name}() {{")
        lines.append("        StringBuilder sb = new StringBuilder();")
        for chunk in chunks:
            lines.append(f'        sb.append("{chunk}");')
        lines.append("        return Base64.getDecoder().decode(sb.toString());")
        lines.append("    }")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)

def main():
    gentype = "py"
    files = [ ]
    output = ""

    if len(sys.argv) > 2:
        for arg in sys.argv[1:]:
            if arg == "-py" or arg == "-python":
                gentype = "py"
            elif arg == "-js" or arg == "-javascript":
                gentype = "js"
            elif arg == "-go" or arg == "-golang":
                gentype = "go"
            elif arg == "-java":
                gentype = "java"
            else:
                files.append(arg)
                
    else:
        gentype = input("output type (py, js, go, java): ")
        while True:
            path = input("filepath (ENTER to finish): ")
            if path in ["", "\n", "\r", "\r\n"]:
                break
            else:
                files.append(path)

    if gentype == "py":
        output = generate_python(files)
    elif gentype == "js":
        output = generate_javascript(files)
    elif gentype == "go":
        output = generate_go(files)
    elif gentype == "java":
        output = generate_java(files)
    else:
        print("invalid output type:", gentype)
    with open("output." + gentype, 'w', encoding='utf-8') as f:
        f.write(output)

if __name__ == "__main__":
    main()
