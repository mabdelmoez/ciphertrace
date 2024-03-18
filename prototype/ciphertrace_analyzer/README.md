# Info
- Developed with VSCode, on Ubuntu 18 LTS (WSL). Executed on WSL, Ubuntu 14.04.6 LTS, and some even were executed on Windows bash such as CipherTrace Verifier, and Visualizer.
- You can see USAGE.md file under each module's directory, for info too. The modules are quite standalone to run.

# PREREQUISITEs
1. PANDA (Note: we use it in ASID mode)
2. python 2.7.15+ (if 3.x, change import ConfigParser as configparser, and maybe a couple of iteritems() to items())
3. pip install ConfigParser, numpy, py2neo, ipython==5.8.0, enum34
4. Neo4J to be installed, v3.5.14 was used. Simply, install Neo4J Desktop on Windows, or for Ubuntu follow: https://www.techunits.com/topics/setup-guides/setup-guide-for-neo4j-graph-database-ubuntu-18-04-lts/. And add the connection details in the main.cfg
5. You need to prepare the database: if it is a fresh install, change password of the neo4j user via this command "curl -H "Content-Type: application/json" -XPOST -d '{"password":"mypassword"}' -u neo4j:neo4j http://localhost:7474/user/neo4j/password".

# Troubleshooting
1. If there is an issue with ipython, make sure you have prompt_toolkit=1.0.18, that comes with ipython=5.8.0

# Modules
The main module handles the config, as well as the following:
## Essential
1. Randometer: Information measurement, to determine the high random caller.
2. Analyzer: Analyses the func_stats file by caller.

## Extra
1. Tester: Tests the main piece of the analyzer, the crypto element finder algorithm.
2. Visualizer: Visualizes the graph file of the analyzer. 
3. Verifier: Verifies the tap points, as per to searchterms, in light, heavy and default modes.
Note: Vsiualizer can be executed on Windows (Bash)

# Analysis Lifecycle
1. Run 'asidstory' plugin to identify the ASID. You can also notice many things there.
2. With that ASID, you can run 'func_stats' plugin. You get func_stats.out.
3. Then run 'unigrams' plugin. You get unigram files for read and writes.
4. Randometer processes your unigram files, and outputs caller(s).
5. Analyzer takes these caller(s), and starts the analysis. You get a graph file, and two tap points' files for potential message(s) and key(s).
6. Run the 'textprinter' plugin with these tap points' file (Note: ASID mode, 0). You get tap buffers' files for reads and writes.
7. Verifier searches over these tap buffers' files, provided a searchterms file, contianing what you are looking for, a simple way to validate the findings or the application. In its Heavy mode, it does the same but searching of a directory containing the ordered (split) tap buffers' dat files-- obtained by split_taps.py script in PANDA scripts. In its Light mode, it simply searches for matches between the string_matches.txt (output of PANDA stringsearch) and the tap points reported by the Analyzer.
8. Visualizer takes the graph file, and visualizes it over Neo4J.
Note: We use IDA Free to export the symbols (function names), and that marks the optional input to the Analyzer and Visualizer.

# Steps
0. Go to main directory of CipherTrace analyzer, where the main.py resides. In other words, make your 'pwd' the "ciphertrace_analyzer"
1. Identify the ASID that you want to examine, e.g., via running the 'asidstory' plugin.
2. Set the ASID, in its property in the main.cfg, property name is "ASID"
3. Revise the commands section the main.cfg, make the commands point to where your analysis files are. Replace "__testdata__/aes128" with your location, of course with the respective file location.

# Usage
Run the ./main.py, or any of the .py file of a module, they are standalone.

# Notes
- Filenames, values, and even configs are the default ones, sure can be changed, just make sure to reflect the changes everywhere.
- All outputs will be in the same directory, from where you run the script.