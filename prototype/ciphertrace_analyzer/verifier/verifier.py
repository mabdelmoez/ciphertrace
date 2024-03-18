import gzip, logging, os
from datetime import datetime

# Naive function to check if a list is  
# contained in another list without breaking order 
def aListInBList(A, B): 
    for i in range(len(B)-len(A)+1): 
        for j in range(len(A)): 
            if B[i + j] != A[j]: 
                break
        else: 
            return {'result': True, 'startingAt': i} #starts at B[i], ends at B[j]
    return {'result': False, 'startingAt': None}
  
  
def main(search_terms, read_buffers, write_buffers, dataidx):
    # Configuration options
    start_time = datetime.now()
    logging.basicConfig(level=logging.INFO, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
    logging.info("Starting Verifier at %s" % (start_time))
    logging.debug("Reading search data")
    # Read search data
    searchdata_f = open(search_terms)
    search_terms_list = list() # list of lists
    for line in searchdata_f:
        search_terms_list.append(line.strip().replace("\n", "").split(' ')) # TODO: extend?
    logging.debug("Reading buffers")
    if read_buffers.endswith('.gz'):
        read_buffers_file = gzip.GzipFile(read_buffers)
    else:
        read_buffers_file = open(read_buffers)
    if write_buffers.endswith('.gz'):
        write_buffers_file = gzip.GzipFile(write_buffers)
    else:
        write_buffers_file = open(write_buffers)
    # Handle buffers
    r_data_list = list()
    w_data_list = list()
    logging.debug("Collecting read buffers")
    logging.warn("Using index %s for read data buffers" % (dataidx))
    for rline in read_buffers_file:
        rdata = str()
        try:
            rdata = rline.split(' ')[int(dataidx)] #TODO: differs for diff os
            r_data_list.append(rdata.strip().replace("\n", ""))
        except IndexError:
            logging.warn("Index %s for data is incorrect" % (dataidx))
    logging.debug("Collecting write buffers")
    logging.warn("Using index %s for write data buffers" % (dataidx))
    for wline in write_buffers_file:
        rdata = str()
        try:
            wdata = wline.split(' ')[int(dataidx)] #TODO: differs for diff os
            w_data_list.append(wdata.strip().replace("\n", ""))
        except IndexError:
            logging.warn("Index %s for data is incorrect" % (dataidx))
    logging.debug("Searching buffers")
    # Search in buffers
    for idx,sdlist in enumerate(search_terms_list):
        #logging.debug("Searching %s buffers for %s" % (r_data_list, search_terms_list[idx]))
        r_contains_result = aListInBList(sdlist,r_data_list) 
        if r_contains_result['result'] == True:
            logging.info("Data Series %s was found in the read tap buffers, starting from line %s till %s" % (str(idx+1), str(r_contains_result['startingAt']), str(r_contains_result['startingAt']+len(sdlist))))
        #logging.debug("Searching %s buffers for %s" % (w_data_list, search_terms_list[idx]))
        w_contains_result = aListInBList(sdlist,w_data_list)
        if w_contains_result['result'] == True:
            logging.info("Data Series %s was found in the write tap buffers, starting from line %s with till %s" % (str(idx+1), str(w_contains_result['startingAt']), str(w_contains_result['startingAt']+len(sdlist))))        
    logging.info("Verifier finished searching %d lines in buffers at %s" % (len(search_terms_list), datetime.now()))
    
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Search for data in some buffers')
    parser.add_argument('-d', '--searchterms', help='multiple line file containing what you are searching for (in space separated hex format). E.g., 01 02 03 04')
    parser.add_argument('-r','--readbuffers', default='write_tap_buffers.txt.gz', help='log file containing read tap point data (can be gzipped)')
    parser.add_argument('-w','--writebuffers', default='read_tap_buffers.txt.gz', help='log file containing write tap point data (can be gzipped)')
    parser.add_argument('-di','--dataidx', default=23, help='the data index in the buffers array (default: 23 for win7sp1)')
    args = parser.parse_args()
    main(search_terms=args.searchterms, read_buffers=args.readbuffers, write_buffers=args.writebuffers, dataidx=args.dataidx)