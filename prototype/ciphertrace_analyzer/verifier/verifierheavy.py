import os, logging
from datetime import datetime

def main(datdir, search_terms):
    start_time = datetime.now()
    logging.basicConfig(level=logging.INFO, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
    logging.info("Starting Verifier Heavy at %s" % (start_time))
    data_list = []

    # Read search data
    searchdata_f = open(search_terms)
    search_terms_list = list() # list of lists
    for line in searchdata_f:
        search_terms_list.append(line.strip().replace("\n", "").replace(' ', "")) 

    for subdir, dirs, files in os.walk(datdir):
        for file in files:
            ext = os.path.splitext(file)[-1].lower()
            if ext in  ('.dat') and ext != '':
                    dfile = os.path.join(subdir, file)
                    logging.info("Reading dat file %s" %(dfile))
                    with open(dfile) as file:
                        dafile = file.read().encode('hex')
                        data_list.append(dafile)
                        #for line in file:
                        #  data = line.encode('hex')
                        #  data_list.append(data.strip().replace("\n", ""))
        

    for idx,sdlist in enumerate(search_terms_list):
        for line in data_list:
            if sdlist in line:
                logging.info("FOUND %s" %(sdlist))
    
    logging.info("Verifier heavy finished searching %d lines in %s dat files at %s" % (len(search_terms_list), len(data_list), datetime.now()))
    
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Search for data in dat files (splitted taps)')
    parser.add_argument('-d', '--searchterms', default="searchterms.txt", help='multiple line file containing what you are searching for (in space separated hex format). E.g., 01 02 03 04')
    parser.add_argument('-dd','--datdir', help='the directory where ".dat" files reside')
    args = parser.parse_args()
    main(search_terms=args.searchterms, datdir=args.datdir)