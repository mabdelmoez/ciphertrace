import os, logging
from collections import defaultdict
from datetime import datetime

def main(tapdir, matchesfile):
   # Configuration options
   start_time = datetime.now()
   logging.basicConfig(level=logging.DEBUG, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
   logging.info("Starting Verifier light at %s" % (start_time))
   
   matches = list()
   logging.info("Reading matches file %s" %(matchesfile))
   with open(matchesfile,'r') as file:
      matches = [line.strip() for line in file]
   result_pcs = defaultdict(int)
   result_callers = defaultdict(int)
   logging.info("Reading .tap files in directory file %s" %(tapdir))
   for subdir, dirs, files in os.walk(tapdir):
      for file in files:
         ext = os.path.splitext(file)[-1].lower()
         if ext in  ('.tap') and ext != '':
               tfile = os.path.join(subdir, file)
               logging.info("Reading tap file %s" %(tfile))
               with open(tfile) as file:
                  for line in file:
                     spaces_count = line.count(' ')
                     if spaces_count > 0:
                        for i in range(spaces_count):
                           content = line.split(' ')[i]
                           for matchline in matches:
                              if content in matchline and i==0:
                                 result_callers[content]+=1
                              if content in matchline and i==1:
                                 result_pcs[content]+=1

   logging.debug("Callers found: %s" % (result_callers))
   logging.debug("PCs found: %s" % (result_pcs))
   if result_callers and result_pcs:
      logging.info("The verifier should find data series")
   else:
      logging.warn("The verifier may not find data series")
   logging.info("Verifier light finished searching PCs and Callers in %s matches at %s" % (len(matches), datetime.now()))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Match tap files with string searches')
    parser.add_argument('-td', '--tapdir', help='directory where ".tap" files reside')
    parser.add_argument('-mf','--matchesfile',  help='string matches text file')
    args = parser.parse_args()
    main(tapdir=args.tapdir, matchesfile=args.matchesfile)