# Info 
This is the Ciphertrace's autorun shell script. It runs PANDA and CipherTrace Analyzer on as many replays as needed. The script runs in two stages, in other words two options. Option 1: runs 'asidstory' to get you all ASIDs in a replay, so that you can pick from which to explore with Option 2-- which runs CipherTrace. See the steps below.

# PREREQUISITEs
- See 'cryphertrace_analyzer' Readme. Most notably,
    - Placed the 'searchterms.txt' file in each replay directory. That is for CipherTrace Verifier.
    - Optional: Place the func_db file, or the symbols file for CipherTrace Analyzer.
- PANDA must be built. Note the 'path' in '/{path}/panda-re/panda/build/i386-softmmu/panda-system-i386', we are going to need it later.

# Steps 
1. Create your replays.
2. Edit the autorun.sh shell script
    1. and insert all replay names in the REPLAYS variable. 
    2. Correct the value of 'panda2m-system-i386' alias, specifically speaking the {path} to your appropriate PANDA build.
    3. If you have got your ASIDs, place them in the ASIDs variable, in the same order as your replays. Each ASID allined by order with its appropriate replay. If you don't know yet the ASIDs, keep reading (See No. 6 below)
2. Place each of them in a directory named after the replay name.
3. Go to the parent directory under which all the replays directories reside.
4. Make a symlink to where autorun.sh script is e.g., 'ln -s {path]/autorun.sh autorun.sh'
5. Make another symlink to where ciphertrace_analyzer resides e.g., 'ln -s {path}/ciphertrace_analyzer/ ciphertrace_analyzer'
6. Run the autorun shell script via 'source autorun.sh |& tee autorun.output'. Note if this is the first time you run the script, chose option 1.
    - Using 'source' makes it run in the same process, so commands such as 'cd' will be reflected appropriately.
    - Using '|& tee' will pipe output including 'std' to a file for review later, additionally will display them on the terminal.

# Notes
- Filenames, values, aliases are the default ones, sure can be changed if you reflect that change in the commands used in the script.
- All outputs will be in the replay directory-- each will contain its different outputs.
- Script supports multiple ASIDs per replay, just separate them by a colon (':')