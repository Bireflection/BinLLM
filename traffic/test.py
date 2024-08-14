import subprocess


# os.system(f"python3 ../ghidra_scripts/BinLLM_single.py --name={file.filename} > /dev/null 2>&1\n")
subprocess.run(
    f"python3 ../ghidra_scripts/BinLLM_single.py --name=CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_01-bad\n",
    shell=True,
    # stdout=subprocess.DEVNULL,
    # stderr=subprocess.DEVNULL
)