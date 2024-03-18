import json, sys, logging, os
from datetime import datetime
from pydoc import locate

def test_cryptoelement_finder(file, celement, moduledir):
    sys.path.insert(1, moduledir)
    from cryptoelementfinder import celement_finder, solve
    out_total_result = dict()
    out_total_result['scheduling'] = dict()
    out_total_result['scheduling']['result'] = dict() # dict by ep, containing ep (dupl), functionstack, r
    out_total_result['scheduling']['count'] = int()
    out_total_result['sbox'] = dict()
    out_total_result['sbox']['result'] = dict()
    out_total_result['sbox']['count'] = int()
    out_total_result['mixing'] = dict()
    out_total_result['mixing']['result'] = dict()
    out_total_result['mixing']['count'] = int()
    out_total_result['initkround'] = dict()
    out_total_result['initkround']['result'] = dict()
    out_total_result['initkround']['count'] = int()
    out_total_result['kround'] = dict()
    out_total_result['kround']['result'] = dict()
    out_total_result['kround']['count'] = int()
    out_total_result['shifting'] = dict()  
    out_total_result['shifting']['result'] = dict()
    out_total_result['shifting']['count'] = int()
    callers = set()
    func_stats = []
    index = 1
    with open(file) as f:
        for line in f:
            idxd_line = json.loads(line)
            idxd_line['idx'] = index
            idxd_line['aggregated'] = 1 # added to count for aggregated results
            index = index + 1
            func_stats.append(idxd_line)
    aggregatedFilteredStack = solve(func_stats, 'entrypoint', ['maxexecs', 'aggregated']) # or maxexecs_addr
    celement_find = locate("cryptoelementfinder.CElement." + celement)
    celement_finder(celement_find, set(), out_total_result, aggregatedFilteredStack, func_stats)
    for ep in out_total_result[celement]['result']:
        for item in out_total_result[celement]['result'][ep]:
            if item['r']['found']:
                callers.add(item['r']['record']['caller'])
                        
    logging.info("Found %s %s crypto element(s), with callers: %s" %(out_total_result[celement]['count'], celement, callers))

def main(file, celement, moduledir):
    start_time = datetime.now()
    logging.basicConfig(level=logging.DEBUG, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
    logging.info("Starting Tester at %s" % (start_time))
    test_cryptoelement_finder(file, celement, moduledir)
    logging.info("Tester finished at %s" % (datetime.now()))
   

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test analyzer (cryptoelementfinder)')
    parser.add_argument('-t', '--testdata', help='data to test (stack records or function calls)')
    parser.add_argument('-p', '--celement', default='kexp', help='crypto element name, from the enum in in crypto element finder (default: kexp)')
    parser.add_argument('-md', '--moduledir', help='analyzer module directory location (which contain the cryptoelementfinder.py)')
    args = parser.parse_args()
    main(file=args.testdata, celement=args.celement, moduledir=args.moduledir)