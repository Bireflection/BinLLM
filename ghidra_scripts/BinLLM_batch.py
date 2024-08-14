#!/usr/bin/env python2
import os
import sys
import readline
import yaml
import json
import re
import shutil
from openai import OpenAI

readline.set_completer_delims(' \t\n=')
readline.parse_and_bind("tab: complete")
os.environ["CUDA_VISIBLE_DEVICES"] = "1"

name = "Test"
result_dir="../BinLLM_Output/Potentially Vulnerable/" + name + "/"
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
        max_tokens=2000, 
        n=1, 
        stop=None,  
        temperature=0.7, 
    )

    return response.choices[0].message.content.strip()



def main():
    result=[]

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "../ghidra_11.0.3_PUBLIC/support/analyzeHeadless"

    if not os.path.isfile(dir_path + '/BinLLM.py'):
        print("Please copy BinLLM.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + '/ghidra_analysis_options_prescript.py'):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    if not os.path.exists("../BinLLM_Output/Decompile_result/"+ name):
        os.makedirs("../BinLLM_Output/Decompile_result/"+ name)
    if not os.path.exists("../BinLLM_Output/Potentially Vulnerable/"+ name):
        os.makedirs("../BinLLM_Output/Potentially Vulnerable/"+ name)
    if not os.path.exists("../BinLLM_Output/Potentially Vulnerable/time_"+ name):
        os.makedirs("../BinLLM_Output/Potentially Vulnerable/time_"+ name)
    
    with open("base_config.yaml", 'r') as file:
        config = yaml.safe_load(file)
        config['output_prompt_directory'] = name
        config['output_dest_src_directory'] = name
        config['output_time_log'] = 'time_' + name
    with open("base_config.yaml", 'w') as file:
        yaml.safe_dump(config, file, sort_keys=False)

    shutil.copyfile("base_config.yaml", "config.yaml")
    while True:
        program_to_analyze_directory = "../Dataset/" + name
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory+="/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)
    for program in os.listdir(result_dir):
        pre=program.split("-")[0]
        middle=program.split("-")[1]
        result.append(pre+"-"+middle)

    for program in os.listdir(program_to_analyze_directory):
        if program in result:
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
                shutil.copyfile("base_config.yaml", "config.yaml")

                folder_path = "../BinLLM_Output/Decompile_result/"+ name
                for filename in os.listdir(folder_path):
            
                    if filename.endswith(".json") and filename.startswith(program):
                        print(filename)
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
                            elements = [elem.strip() for elem in match.split(',')]
                            result.append(elements)
                        print(result)
                        add_sink_function("base_config.yaml", "config.yaml", result, 'sink')
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
                        add_sink_function("base_config.yaml", "config.yaml", result, 'source')
            except:
                pass        
                
            print("++++++++++++++++++++++++++++\n")
            os.environ['PROGRAM_NAME'] = program
            os.system("sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(ghidra_path, program_to_analyze_directory, program_to_analyze_directory+'/'+program, dir_path + "/ghidra_analysis_options_prescript.py", dir_path + "/BinLLM.py"))
            print("-------------Finish {}------------------\n".format(program))
            print("++++++++++++++++++++++++++++\n")

    print("-------------Finish all------------------\n")
if __name__ == "__main__":
    main()
