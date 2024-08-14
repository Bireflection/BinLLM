from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import os

os.environ["CUDA_VISIBLE_DEVICES"] = "1"
model_path = '/home/shisenyou/Taint/ghidra_scripts/llm4decompile-6.7b-v2'  # V2 Model

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForCausalLM.from_pretrained(model_path, torch_dtype=torch.bfloat16).cuda()

with open('./ghidra_scripts/1.txt','r') as f:#optimization level O0
    asm_func = f.read()
inputs = tokenizer(asm_func, return_tensors="pt").to(model.device)
with torch.no_grad():
    outputs = model.generate(**inputs, max_new_tokens=2048)### max length to 4096, max new tokens should be below the range
c_func_decompile = tokenizer.decode(outputs[0][len(inputs[0]):-1])

with open('./ghidra_scripts/1.txt','r') as f:#original file
    func = f.read()

print(f'pseudo function:\n{func}')# Note we only decompile one function, where the original file may contain multiple functions
print(f'refined function:\n{c_func_decompile}')