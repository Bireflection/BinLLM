#!/usr/bin/env python2
import os
import sys
import readline
import time
import yaml
import json
import re
import shutil
from openai import OpenAI
import argparse
 
parser = argparse.ArgumentParser()
parser.add_argument("--name", default="", help="名称")
args = parser.parse_args()
readline.set_completer_delims(' \t\n=')
readline.parse_and_bind("tab: complete")
os.environ["CUDA_VISIBLE_DEVICES"] = "1"

name = args.name
result_dir="/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/" + name + "/"
prompt_source = "Please use the function name to find the function that can directly receive external input or generate pseudo random number as the taint source in the taint analysis. Function names without semantic information are ignored. And output **only** in the form of [function name, external input corresponding parameters order or return value(use ret to represent)] without other description."
prompt_sink = "For taint analysis, please use the function name to find the taint sink that may lead to vulnerabilities such as command hijacking, buffer overflow, format string, etc. Function names without semantic information are ignored. And output only in the form of [function name, parameter order corresponding to the vulnerability] without other description."
prompt_content="Based on the provided content only, please analyze whether the function has variables that control the loop or participate in calculations that may cause integer overflow or division by zero errors. If the variable exists, further analyze whether there is a dependency relationship with function parameters or external inputs. If there is such a variable, please output it in the form of [function name, the variable name, loop or calculation] without additional description. Returns 'No' if no such variable exists."

def add_sink_function(source_yaml, dest_yaml, new_functions, type):

    # Read the copied YAML file
    with open(dest_yaml, 'r') as file:
        config = yaml.safe_load(file)

    # Check if 'sink_functions' exists in the config
    if type == 'sink':
        if 'sink_functions' not in config:
            config['sink_functions'] = {}

        # Add new sink functions
        for item in new_functions:
            if item[0] in config['sink_functions']:
                config['sink_functions'][item[0]].extend(item[1])
            else:
                config['sink_functions'][item[0]] = []
                config['sink_functions'][item[0]].append(eval(item[1]))
    else:
        if 'taint_labels' not in config:
            config['taint_labels'] = {}

        # Add new sink functions
        for item in new_functions:
            if item[0] in config['taint_labels']:
                config['taint_labels'][item[0]][0].extend(item[1])
            else:
                print(item[0])
                config['taint_labels'][item[0]] = []
                config['taint_labels'][item[0]].append(eval(item[1]))
                config['source_functions'].append(item[0])

        

    # Write the updated config back to the destination YAML file
    with open(dest_yaml, 'w') as file:
        yaml.safe_dump(config, file, sort_keys=False)


def generate_response(messages):
    client = OpenAI(api_key="sk-xxx",
                    base_url="https://api.deepseek.com")
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=messages,
        max_tokens=4000, 
        n=1, 
        stop=None,  
        temperature=0.7, 
    )

    return response.choices[0].message.content.strip()

def llm4decompile(func):
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch
    from tqdm import tqdm

    model_path = '/home/shisenyou/Taint/ghidra_scripts/llm4decompile-6.7b-v2'  # V2 Model

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path, torch_dtype=torch.bfloat16).cuda()

    inputs = tokenizer(func, return_tensors="pt").to(model.device)
    
    # Estimate the number of iterations based on the length of the input
    num_iterations = inputs['input_ids'].shape[1]
    
    # Initialize the progress bar
    with torch.no_grad():
        with tqdm(total=num_iterations, desc="Decompiling", unit="step") as pbar:
            outputs = model.generate(**inputs, max_new_tokens=1024)  # max length to 4096, max new tokens should be below the range
            pbar.update(num_iterations)  # Complete the progress bar after generation

    c_func_decompile = tokenizer.decode(outputs[0][len(inputs['input_ids'][0]):-1])
    return c_func_decompile

def main():
    result=[]

    dir_path = os.path.dirname(os.path.realpath(__file__))
    print(dir_path)
    ghidra_path = "/home/shisenyou/Taint/ghidra_11.0.3_PUBLIC/support/analyzeHeadless"

    if not os.path.isfile(dir_path + '/BinLLM.py'):
        print("Please copy BinLLM.py to the same directory as this script")
        sys.exit(1)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    if not os.path.exists("/home/shisenyou/Taint/BinLLM_Output/Decompile_result/"+ name):
        os.makedirs("/home/shisenyou/Taint/BinLLM_Output/Decompile_result/"+ name)
    if not os.path.exists("/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/"+ name):
        os.makedirs("/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/"+ name)
    if not os.path.exists("/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/time_"+ name):
        os.makedirs("/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/time_"+ name)
    
    with open("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", 'r') as file:
        config = yaml.safe_load(file)
        config['output_prompt_directory'] = name
        config['output_dest_src_directory'] = name
        config['output_time_log'] = 'time_' + name
    with open("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", 'w') as file:
        yaml.safe_dump(config, file, sort_keys=False)

    shutil.copyfile("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", "/home/shisenyou/Taint/ghidra_scripts/config.yaml")
    while True:
        program_to_analyze_directory = "/home/shisenyou/Taint/samples/"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory+="/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)


    for program in os.listdir(program_to_analyze_directory):
        print(program)
        st = time.time()
        if program != name:
            print("Result existing\n")
            pass
        else:
            print("++++++++++++++++++++++++++++\n")
            os.environ['PROGRAM_NAME'] = program
            os.system("sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(ghidra_path, program_to_analyze_directory, program_to_analyze_directory+'/'+program, dir_path + "/ghidra_analysis_options_prescript.py", dir_path + "/BinLLM.py"))
            print("-------------Finish {}------------------\n".format(program))
            print("++++++++++++++++++++++++++++\n")
            
            try:
                pattern = r'\[([^\[\]]+)\]'
                shutil.copyfile("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", "/home/shisenyou/Taint/ghidra_scripts/config.yaml")

                folder_path = "/home/shisenyou/Taint/BinLLM_Output/Decompile_result/"+ name
                for filename in os.listdir(folder_path):
            
                    if filename.endswith(".json") and filename.startswith(program):
                        print(filename)
                        print("!!!!!!!!!!!!!!!!!!!!!!!!!1")
                        file_path = os.path.join(folder_path, filename)
                        
            
                        with open(file_path, 'r' )as file:
                            data = json.load(file)
                            messages = [
                            {"role": "system",
                                "content": "You are a helpful assistant to help with Binary Taint"},
                            {"role": "user", "content": data + prompt_source}
                        ]
                        ans_source = generate_response(messages)
                        matches = re.findall(pattern, ans_source)
                        result = []
                        for match in matches:
                            # 将匹配的字符串按逗号分隔并去除空格
                            elements = [elem.strip() for elem in match.split(',')]
                            result.append(elements)
                        print(result)
                        add_sink_function("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", "/home/shisenyou/Taint/ghidra_scripts/config.yaml", result, 'sink')
                        print("++++++++++++++++++++++++++++\n")
                        with open(file_path, 'r' )as file:
                            data = json.load(file)
                            messages = [
                            {"role": "system",
                                "content": "You are a helpful assistant to help with Binary Taint"},
                            {"role": "user", "content": data + prompt_sink}
                        ]
                        ans_sink = generate_response(messages)
                        matches = re.findall(pattern, ans_sink)
                        result = []
                        for match in matches:
                            elements = [elem.strip() for elem in match.split(',')]
                            result.append(elements)
                        print(result)
                        add_sink_function("/home/shisenyou/Taint/ghidra_scripts/base_config.yaml", "/home/shisenyou/Taint/ghidra_scripts/config.yaml", result, 'source')
                        with open(file_path, 'r' )as file:
                            data = json.load(file)
                            messages = [
                            {"role": "system",
                                "content": "You are a helpful assistant to help with Binary Taint"},
                            {"role": "user", "content": data + "Find out the function call chain, and represent it like:main() -> functionA() -> functionB() -> functionC(). Only give the chain and do not output anything else."}
                        ]
                        chain = generate_response(messages)
                        print(chain)
                        with open("/home/shisenyou/Taint/output/" + name + "call_chain.md", "w") as f:
                            f.write(chain)

            except:
                print("ERROR ")

    
                
            print("++++++++++++++++++++++++++++\n")
            os.environ['PROGRAM_NAME'] = program
            os.system("sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(ghidra_path, program_to_analyze_directory, program_to_analyze_directory+'/'+program, dir_path + "/ghidra_analysis_options_prescript.py", dir_path + "/BinLLM.py"))
            print("-------------Finish {}------------------\n".format(program))
            print("++++++++++++++++++++++++++++\n")
            def extract_prompt(content):
                return content[0]
            print(time.time() - st)
            root_dir = "/home/shisenyou/Taint/BinLLM_Output/Potentially Vulnerable/" + name
            
            tested = False 
            prompt_all = ""
            for root, dirnames, filenames in os.walk(root_dir):
                for filename in filenames:
                    if filename.startswith(name):
                        tested = True
                        file_path = os.path.join(root, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as file:
                                content = json.load(file)

                                # 提取 promt
                                prompt = extract_prompt(content)
                                start_marker = "Output as a data flow."

                                start_index = prompt.find(start_marker) + len(start_marker)

                                if start_index != -1:
                                    extracted_func = prompt[start_index:]
                                    
                                    with open("/home/shisenyou/Taint/output/" + name + "_extract_func", "w") as f:
                                        f.write(extracted_func)
                                    print("Before calling llm4decompile")
                                    with open("/home/shisenyou/Taint/output/" + name + "_extract_func", "r") as f:
                                        extracted_func = f.read()
                                    refined_func = llm4decompile(extracted_func)
                                    print("After calling llm4decompile")
                                    prompt = prompt[:start_index] + " " + refined_func
                                    with open("/home/shisenyou/Taint/output/" + name + "_refined_func", "a") as f:
                                        f.write(refined_func)
                                    print(prompt)
                                    prompt_all += prompt
                                    
                                else:
                                    print("NOT found")

                        except Exception as e:
                            print(f"Error reading file {file_path}: {e}")
                            continue
                                            # 构造 message
            messages = [
                {"role": "system",
                    "content": "You are a helpful assistant to help with Binary Taint"},
                {"role": "user", "content": prompt_all +
                    "Based on the above taint analysis results, analyze whether the code has vulnerabilities in the code. If there is a vulnerability, please explain what kind of vulnerability it is according to CWE. Think step by step, and separate your answer to 5 parts: Taint Analysis, Data Flow, Vulnerability identification, CWE identification and Conclusion. Pay attention to CWE78, 134, 190. There may be a vulnerability, Please tell me the most relevant CWE number at the very end in the form of **存在CWE-index漏洞**. Else, print \"NO CWE\". Think step by step. Return in Chinese, Taint Analysis, Data Flow, Vulnerability identification, CWE identification and Conclusion in Chinese is respectively 污点分析, 数据流, 漏洞分析. CWE识别, 总结"}
            ]

            # 调用 GPT
            answer = generate_response(messages)

            with open("/home/shisenyou/Taint/output/" + name + ".md", "w") as f:
                f.write(answer)
            print("----------------------------------------------------")
            if not tested:
                shutil.copyfile("/home/shisenyou/Taint/ghidra_scripts/no_flow.md", "/home/shisenyou/Taint/output/" + name +".md")


    print("-------------Finish all------------------\n")
if __name__ == "__main__":
    main()
