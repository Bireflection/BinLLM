import os
import json
import time
import hashlib
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    file.seek(0)

    print("received file: ", file.filename)

    
    # 保存文件到本地
    file.save(f"../samples/{file.filename}")
    # 运行脚本，获取结果
    # os.system(f"conda activate taint")

    # os.system(f"python3 ../ghidra_scripts/BinLLM_single.py --name={file.filename} > /dev/null 2>&1\n")
    os.system(f"python3 ../ghidra_scripts/BinLLM_single.py --name={file.filename}\n")
    #  subprocess.run(
    #     f"python3 ../ghidra_scripts/BinLLM_single.py --name={file.filename}\n",
    #     shell=True,
    #     stdout=subprocess.DEVNULL,
    #     stderr=subprocess.DEVNULL
    # )
    markdown_result = f"../output/{file.filename}.md"
    call_chain = f"../output/{file.filename}call_chain.md"
    extract_func = f"../output/{file.filename}_extract_func"
    refined_func = f"../output/{file.filename}_refined_func"
    decompile_result = f"../BinLLM_Output/Decompile_result/{file.filename}/{file.filename}-function_name.json"

    time.sleep(1)

    response = {}
    if os.path.exists(markdown_result):
        with open(markdown_result, 'r', encoding='utf-8') as f:
            response["markdown"] = f.read()
            f.seek(0)
    else:
        response["markdown"] = "Markdown file not found"

    if os.path.exists(decompile_result):
        with open(decompile_result, 'r') as f:
            response["decompile"] = f.read()
            f.seek(0)
    else:
        response["decompile"] = "Decompile file not found"

    if os.path.exists(call_chain):
        with open(call_chain, 'r', encoding='utf-8') as f:
            response["call_chain"] = f.read()
            f.seek(0)
    else:
        response["call_chain"] = "call_chain file not found"
    
    if os.path.exists(extract_func):
        with open(extract_func, 'r', encoding='utf-8') as f:
            response["extract_func"] = f.read()
            f.seek(0)
    else:
        response["extract_func"] = "extract_func file not found"

    if os.path.exists(refined_func):
        with open(refined_func, 'r', encoding='utf-8') as f:
            response["refined_func"] = f.read()
            f.seek(0)
    else:
        response["refined_func"] = "refined_func file not found"
    
    with open(f"../samples/{file.filename}", 'rb') as f:
        response["md5"] = hashlib.md5(f.read()).hexdigest()
        f.seek(0)


    # 运行 checksec
    # 构建命令
    command = f"checksec --file=../samples/{file.filename}"

    # 执行命令并捕获输出
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # 获取标准输出
    stdout = result.stdout
    # 获取标准错误输出
    stderr = result.stderr

    response["stdout"] = stdout
    response["stderr"] = stderr

    
    return json.dumps(response), 200, {"Content-Type":"application/json"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # 开放本机5000端口
