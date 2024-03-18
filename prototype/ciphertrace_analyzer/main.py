from datetime import datetime
import logging, os, ConfigParser #Glib format, same as .ini files

def execute_tester(config, cfgfile):
    tester_cmd = config.get('COMMANDS', 'TesterCmd')
    logging.info("Executing Tester: %s " % (tester_cmd))
    os.system(tester_cmd)

def execute_randometer(config, cfgfile):
    randometer_cmd = config.get('COMMANDS', 'RandometerCmd') + " --asid " + config.get('MAIN', 'ASID') + " --readent " + config.get('RANDOMETER', 'EntReadMask')  + " --writeent " + config.get('RANDOMETER', 'EntWriteMask')  + " --readrand " + config.get('RANDOMETER', 'RandReadMask') + " --writerand " + config.get('RANDOMETER', 'RandWriteMask')
    logging.info("Executing Information Measurement (Randometer): %s " % (randometer_cmd))
    os.system(randometer_cmd)

def execute_verifier(config, cfgfile):
    verifierlight_cmd = config.get('COMMANDS', 'VerifierLightCmd') 
    logging.info("Executing Verifier Light: %s " % (verifierlight_cmd))
    os.system(verifierlight_cmd)
    verifier_cmd = config.get('COMMANDS', 'VerifierCmd')  + " --dataidx " + config.get('Verifier', 'DataIndex') 
    logging.info("Executing Verifier Default: %s " % (verifier_cmd))
    os.system(verifier_cmd)
    verifierheavy_cmd = config.get('COMMANDS', 'VerifierHeavyCmd') 
    logging.info("Executing Verifier Heavy: %s " % (verifierheavy_cmd))
    os.system(verifierheavy_cmd)

def execute_visualizer(config, cfgfile):
    visualizer_cmd = config.get('COMMANDS', 'VisualizerCmd') + " --conn " + config.get('Visualizer', 'ConnDetails') 
    logging.info("Executing Visualizer: %s " % (visualizer_cmd))
    os.system(visualizer_cmd)

def execute_analyzer(config, cfgfile, caller, aconfig):
    logging.info("Analyzing for caller: %s started" % (caller))
    analyzer_cmd = config.get('COMMANDS', 'AnalyzerCmd') + " --caller " + caller + " --aconfig " + aconfig
    logging.info("Executing Analyzer: %s " % (analyzer_cmd))
    os.system(analyzer_cmd)
    logging.info("Analyzing for caller: %s finished" % (caller))

def main(config):
    start_time = datetime.now()
    logging.basicConfig(level=logging.DEBUG, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
    logging.info("Started CipherTrace Analysis Engine at %s" % (start_time))
    
    currdir = os.path.dirname(os.path.abspath(__file__))
    cfgfile = os.path.join(currdir, config)
    logging.info("Reading config file %s" % (cfgfile))
    config = ConfigParser.RawConfigParser()
    config.read(cfgfile)

    # Execute tester
    try:
      execute_tester(config, cfgfile)
    except Exception as e: 
      logging.error('Error executing tester: %s' % (e))
      logging.warn("Tester is skipped")

    # Execute Randometer
    try:
      execute_randometer(config, cfgfile)
    except Exception as e:
      logging.error('Error executing randometer: %s' % (e))
      logging.info("Cannot proceed, exiting!")
      exit()

    # Reading randometer.out
    logging.info("Reading randometer output to get the callers to filter by in the analyzer from default out file")
    callers = set()
    try:
      randometer_file = open("randometer.out", "r")
      callers = [x.strip().replace("\n","") for x in randometer_file] 
    except Exception as e:
      logging.error("Error reading randometer default out file. %s" % (e))
      logging.info("Cannot proceed, exiting!")
      exit()
    if not callers:
      logging.error("No callers found in randometer default out file")
      logging.info("Cannot proceed, exiting!")
      exit()
    
    # Prep for executing analyzer
    logging.info("Randometer callers are %s" % (callers)) # 7728a5f0
    first_call_exec = config.get('Analyzer', 'FirstCallerExecusion')
    logging.info("FirstCallerExecusion is %s" % (first_call_exec))
    # Executing analyzer 
    aconfig = config.get('Analyzer', 'Config')
    try:
      if first_call_exec:
        execute_analyzer(config, cfgfile, callers[0], aconfig)
      else:
        for caller in callers:
          execute_analyzer(config, cfgfile, caller, aconfig)
    except Exception as e:
      logging.error('Error executing analyzer: %s' % (e))
      logging.info("Cannot proceed, exiting!")
      exit()
    
    # Execute verifier
    try:
      execute_verifier(config, cfgfile)
    except Exception as e:
      logging.error('Error executing verifier: %s' % (e))
      logging.warn("Verifier is skipped")

    # Execute visualizer
    try:
      execute_visualizer(config, cfgfile)
    except Exception as e:
      logging.error('Error executing visualizer: %s' % (e))
      logging.warn("Visualizer is skipped")
    
    logging.info("CipherTrace Analysis Engine finished at %s" % (datetime.now()))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run CipherTrace Analysis Engine')
    parser.add_argument('-cfn', '--cfgname', help='the main config file')
    args = parser.parse_args()
    main(config=args.cfgname)