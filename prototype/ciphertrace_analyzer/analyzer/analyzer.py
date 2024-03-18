#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json, os, sys, logging
from cryptoelementfinder import *
from datetime import datetime
from helper import most_frequent, most_frequent_2, most_frequent_n, create_tappoints_file, line_prepender_to_file
from reporter import print_callstack, print_result

def main(file, caller, function_names, stack_name, res_confusion, verbose, outfileprefix, aconfig):
    # Configuration options
    start_time = datetime.now()
    func_stats_size = os.path.getsize(file)

    logging.basicConfig(level=logging.INFO, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')
    logging.info("Starting Analyzer for a %s bytes trace %s at %s" % (func_stats_size, file, start_time))

    filter_mainrec = "maxexecs" # filter the main record by maxexecs field
    filter_stacksize = 3 
    filter_compc_writeent = 1.0
    if aconfig:
        logging.info("filtering criteria from config: %s" % (aconfig))
        cfg_arr = aconfig.split(",")
        filter_mainrec = str(cfg_arr[0].strip())
        if filter_mainrec not in ("maxexecs", "llvm_bb"):
            filter_mainrec = "maxexecs"
            logging.warn("%s is not supported, set to default: maxexecs" % (filter_mainrec))
        filter_stacksize = int(cfg_arr[1].strip())
        filter_compc_writeent = float(cfg_arr[2].strip())
    else:
        logging.warn("Analysis config is not passed. filtering criteria (default): mainrecby=maxexecs, stacksize=3, compc_write_entropy=1.0")

    inv_func_map = None
    if function_names:
        logging.info("Reading the symbols file %s" % (function_names))
        # remove 0000000000 first files first. 
        # TODO: fix the name cut
        func_map =  {str(k): v.replace('0000000000', '').split('\t')[2] for line in open(function_names, 'r').readlines() for (k, v) in (line.strip().split(None, 1),)}
        inv_func_map = {v: k for k, v in func_map.items()}
    
    logging.info("Reading the stats file %s" % (file))
    func_stats = []
    
    with open(file) as f:
        for line in f:
            if caller in line: # NEW: Much faster, fixes "not finding results in large files"
                l_dict = json.loads(line)
                l_dict['aggregated'] = 1 # for reporting by aggregation
                func_stats.append(l_dict)

    # Let's filter by callers fetched from randometer
    logging.info("Filtering by caller")
    filteredByCaller = filter(lambda rec: filterCaller(rec, caller), func_stats)
    logging.info("filteredByCaller count: %s" % (len(list(filteredByCaller))))

    logging.info("Collect the records with fields (maxexecs, llvm_bb) that have maximum values") # TODO: can be added in aconfig
    track_fields = track_max_fields(filteredByCaller)
    logging.info("Number of of records with maximum values and filtered by caller %s" %(track_fields))

    logging.info("Find the main stack records (where it all begins, with max values of the %s)" %(filter_mainrec))
    # Let's find the main records, the one with max (filter field) from the filteredByCaller
    mainRecs = [x for x in filteredByCaller if x[filter_mainrec] == track_fields[filter_mainrec]] # NEW: Unnecessary?!
    #mainRecs = track_fields 
    logging.info('mainRecs count: %s' % (len(mainRecs)))
    if verbose == "True":
        for rec in mainRecs:
            logging.debug('mainRecs: %s %s %s %s' % (rec["instr_count"], rec["maxexecs"], rec["maxexecs_addr"], rec["llvm_bb"]))

    # Exclude from filteredByCaller
    logging.info("Exclude the main records from the filtered by caller ones be able to apply stack filtering.")
    callerComprehension = [x for x in filteredByCaller if x not in mainRecs]
    logging.debug("callerComprehension count (excluded mainRecs from filteredByCaller) %s" % (len(callerComprehension)))
    callerComprehension.extend(mainRecs) # to catch more on scattered CFGs, but takes long (~40%), e.g., openssl, but for hmacsha256 finds mixing and shifting
    ucallerComprehension = {str(v[stack_name][:filter_stacksize]):v for v in callerComprehension}.values()
    logging.debug("ucallerComprehension count (using the stack as identifier) %s" % (len(ucallerComprehension)))
    # For each excluded one
    logging.info("Do the analysis for each comprehended caller stack")
    for comprehendedCaller in ucallerComprehension:
        out_total_result = dict()
        out_total_result['scheduling'] = dict()
        out_total_result['scheduling']['result'] = dict() # Note: dict by ep, containing ep (dupl), functionstack
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

        # The stack filter
        stack_filter = comprehendedCaller[stack_name][:filter_stacksize] # get first n from that result.
        logging.info("Stack name: %s" % (stack_name))
        logging.info("Stack filter: %s" % (stack_filter))

        # Filter the records 
        logging.info("Filter the records: those which share the stack filter, and certain stats (arith>1, loop>1, compc_write_entropy>1.0)") # TODO: can be moved to aConfig
        # Get all records that share that stack_filter
        filteredStack = filter(lambda rec: filterStack(rec, stack_name, stack_filter), func_stats)
        # Additionally, filter these records to have certain stats
        filteredStack = filter(lambda rec: filterStats(rec, filter_mainrec, filter_compc_writeent), filteredStack)

        logging.info("Create the graph file (for CFG)")
        # Create CFG input file 
        filenametree = outfileprefix + "_" + comprehendedCaller['entrypoint'] + ".graph"
        with open(filenametree, 'w') as fp:
            for line in filteredStack:
                json.dump(line, fp)
                fp.write("\n")
        fp.close()
        
        logging.info("Aggregate by maxexecs and groupby the entrypoint (function name)")
        # Aggregate by maxexecs, groupby entrypoint
        aggregatedFilteredStackRecs = solve(filteredStack, 'entrypoint', ['maxexecs', 'aggregated']) # Note: or maxexecs_addr
        
        logging.info("Find the crypto elements, as per to certain traits")
        # Find crypto elements per record, as per to the traits
        celement_finder(CElement.scheduling, set(), out_total_result, aggregatedFilteredStackRecs, filteredStack)
        scheduling_prereq = set()
        scheduling_prereq.add(CElement.scheduling)
        celement_finder(CElement.initkround, scheduling_prereq, out_total_result, aggregatedFilteredStackRecs, filteredStack)
        initkround_prereq = set()
        initkround_prereq.add(CElement.initkround)
        celement_finder(CElement.kround, initkround_prereq, out_total_result, aggregatedFilteredStackRecs, filteredStack)
        celement_finder(CElement.sbox, set(), out_total_result, aggregatedFilteredStackRecs, filteredStack) # Note: initkround to be found before, if confusion needs to be resolved
        celement_finder(CElement.mixing, set(), out_total_result, aggregatedFilteredStackRecs, filteredStack)
        mixing_prereq = set()
        mixing_prereq.add(CElement.mixing)
        celement_finder(CElement.shifting, mixing_prereq, out_total_result, aggregatedFilteredStackRecs, filteredStack) 

        # Printing
        logging.debug('Start reporting...')
        # Sort the items by smaller eps first.
        # Don't reverse, to print the results as how the round routine is ordered.
        logging.debug('filtered and aggregated stack records count: %s' % (len(aggregatedFilteredStackRecs.items())))
        for k,v in sorted(aggregatedFilteredStackRecs.items(), reverse=False):
            # TODO: a bit awkward, did we break it?
            if inv_func_map and str(k).upper() in inv_func_map: #k is entrypoint
                logging.debug('%s ..) %s - %s' % (inv_func_map[str(k).upper()], str(k), str(v))) # TODO: refer to above name cut todo
            else:
                logging.debug('%s %s - %s' % (str(k), str(k), str(v)))
                
            # Print the point
            logging.info("entrypoint %s" % (str(k)))
            logging.info("maxexecs_addr %s" % (aggregatedFilteredStackRecs[str(k)]['maxexecs_addr']))
           
            # report the found crypto elements, and resolve any confusion
            if str(k) in out_total_result['scheduling']['result'].keys():
                logging.info("<----------Scheduling-------------> ")
                if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                    print_result(str(k), k, v, 'scheduling', out_total_result['scheduling']['result'], out_total_result['scheduling']['count'], verbose, inv_func_map)
            if str(k) in out_total_result['initkround']['result'].keys():
                # but still can be confused with scheduling which usually has more arith and store (even in sum)
                if res_confusion == "False":
                    logging.info("<----------KRoundInit------------->")
                    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                        print_result(str(k), k, v, 'initkround', out_total_result['initkround']['result'], out_total_result['initkround']['count'], verbose, inv_func_map)
            if str(k) in out_total_result['kround']['result'].keys():
                # but still can be confused with scheduling which usually has more arith and store (even in sum)
                if res_confusion == "False":
                    logging.info("<----------KRound------------->")
                    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                        print_result(str(k), k, v, 'kround', out_total_result['kround']['result'], out_total_result['kround']['count'], verbose, inv_func_map)
            if str(k) in out_total_result['sbox']['result'].keys():
               # but still can be confused with rounder which usually has more arith and store
                if res_confusion == "False":
                    logging.info("<----------S-Box------------->")
                    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                        print_result(str(k), k, v, 'sbox', out_total_result['sbox']['result'], out_total_result['sbox']['count'], verbose, inv_func_map)
            if str(k) in out_total_result['mixing']['result'].keys():
                # but can be confused with boxer, in which store ops are less, and arith are less
                if res_confusion == "False": 
                    logging.info("<----------Mixing------------->")
                    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                        print_result(str(k), k, v, 'mixing', out_total_result['mixing']['result'], out_total_result['mixing']['count'], verbose, inv_func_map)
            if str(k) in out_total_result['shifting']['result'].keys():
                # but it can be confused with the boxer, which has more store ops and higher arith
                if res_confusion == "False": 
                    logging.info("<----------Shifting------------->")
                    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                        print_result(str(k), k, v, 'shifting', out_total_result['shifting']['result'], out_total_result['shifting']['count'], verbose, inv_func_map)
            if verbose == "True":
                print_callstack(aggregatedFilteredStackRecs[str(k)]["functionstack"], inv_func_map)      

        # Now get all the statebases
        logging.info('Collecting state bases')
        state_bases = dict()
        state_bases['dict'] = dict()
        state_bases['baseset'] = set()
        state_bases['lenlist'] = list()
        statebase_set = set()
        statebaselen_list = list()
        for celement in out_total_result:
            for ep in out_total_result[celement]['result']:
                for item in out_total_result[celement]['result'][ep]:
                    if item['r']['state']['statebase']:
                        statebase_set.add(item['r']['state']['statebase'])
                        statebaselen_list.append(item['r']['state']['len'])
                        if item['r']['state']['statebase'] in state_bases:
                            state_bases['dict'][item['r']['state']['statebase']] = item['r']['state']
                        else: 
                            state_bases['dict'][item['r']['state']['statebase']] = dict()
        state_bases['baseset'] = statebase_set
        state_bases['lenlist'] = statebaselen_list
        
        if state_bases['baseset'] and len(state_bases['baseset']) > 0: 
            logging.info("Report overall stats")
            logging.info("entrypoint of comprehended caller %s" % (comprehendedCaller['entrypoint']))
            logging.debug("State bases %s" % (state_bases))


        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            logging.debug("Report potential keys found")
            # Get me all key records (keyrecord)
            for idx, ep in enumerate(out_total_result['scheduling']['result']):
                    for item in out_total_result['scheduling']['result'][ep]:
                        logging.info("Key %s: %s" % (idx+1, item['r']['keyrecord']))
        
        logging.info('Collect & report routines/functions, max 3 if there are duplicates')
        # Find the routines
        # The round routine is (caller of func)
        # The main function is (caller of round)
        # The function, returns from the functionstack, the prev, and prev-1
        # TODO: Improve CFG analysis to find true round or main
        # TODO: Improve Error handling?
        routines = report_routines_func(out_total_result) 
        report_routines = routines['routines_dict']
        all_round_list = routines['all_round_list']
        all_main_list = routines['all_main_list']

        # For the entrypoint
        for ep in report_routines:
            if inv_func_map and ep.upper() in inv_func_map:
                logging.debug("For entrypoint: %s" % (inv_func_map[ep.upper()]))
            else:
                logging.debug("For entrypoint: %s" % (ep))
            
            # The round routine is
            round_routines = most_frequent_2(report_routines[ep]['round']) # max 3 routines are reported if there are duplicates
            for routine in round_routines:
                round_routine_name_report = None
                if inv_func_map and routine.upper() in inv_func_map:
                    round_routine_name_report = inv_func_map[routine.upper()],
                else:
                    round_routine_name_report = routine
                logging.debug("Round routine is: %s (perc): /1 is %s /%s routines is %s" % (round_routine_name_report, percentage(1, len(report_routines[ep]['round'])), len(round_routines), percentage(len(round_routines), len(report_routines[ep]['round']))))
            
            # The main function is
            main_rotines = most_frequent_2(report_routines[ep]['main']) # max 3 routines are reported if there are duplicates
            for routine in main_rotines:
                main_routine_name_report = None
                if inv_func_map and routine.upper() in inv_func_map:
                   main_routine_name_report = inv_func_map[routine.upper()]
                else:
                   main_routine_name_report = routine
                
                logging.debug("Main function is: %s (perc): /1 is %s /%s routines is %s" % (main_routine_name_report, percentage(1, len(report_routines[ep]['main'])), len(main_rotines), percentage(len(main_rotines), len(report_routines[ep]['main']))))

        # Overall routine reporting
        logging.info("Overall routine reporting")
        mf_round = most_frequent(all_round_list)
        mf_main = most_frequent(all_main_list)
        if mf_round:
            if inv_func_map:
                logging.info("Round routine is: %s ..)" % (inv_func_map[mf_round.upper()] if len(all_round_list) > 0 and mf_round and mf_round.upper() in inv_func_map else mf_round)) # refer to closing names todo
            else: 
                logging.info("Round routine is: %s" % (mf_round)) 
        if mf_main:
            if inv_func_map:
                logging.info("Main function is: %s ..)" % (inv_func_map[mf_main.upper()] if len(all_main_list) > 0 and mf_main and mf_main.upper() in inv_func_map else mf_main)) # refer to closing names todo
            else:
                logging.info("Main function is: %s" % (mf_main))

        # Get reads and writes of main function and find the messages 
        # Note: You depend on finding the correct main function and most frequest length of state to be correct
        logging.info("Collecting tap points data: states (ciphertexts or plaintexts)")

        #mf_state_len = most_frequent(state_bases['lenlist']) # with more records, gets confused
        mf_state_lens = most_frequent_n(state_bases['lenlist'], 3)

        msg_taps = set()
        for rec in filteredStack:
            if rec['entrypoint'] == mf_main:
                for read in rec['reads']:
                    if read['len'] in mf_state_lens: #== mf_state_len: # for reads
                        msg_taps.add(rec['caller'] + " " + read['pc'] + " " + rec['asid'] + "\n")
                for write in rec['writes']:
                    if write['len'] in mf_state_lens: #== mf_state_len: # for writes
                        msg_taps.add(rec['caller'] + " " + write['pc'] + " " + rec['asid'] + "\n") 

        logging.info("Collecting tap points data: key(s)")
        key_taps = set()
        # Build tap points for keys from key record
        for ep in out_total_result['scheduling']['result']:
            for item in out_total_result['scheduling']['result'][ep]:
                if item['r']['found']:
                    key_taps.add(item['r']['record']['caller'] + " " + item['r']['keyrecord']['keyraddrpc'] + " " +item['r']['record']['asid'] + "\n")


        logging.info("Writing tap files (if any)")
        if (len(msg_taps)) > 0:
            # Create the tap points file for msgs
            filenamemsg = outfileprefix + "_" + comprehendedCaller['entrypoint'] + "_states.tap"
            create_tappoints_file(filenamemsg, msg_taps)
            # Add the stack type to the tap point file to make it easy for those who take the file directly as input for the textprinter plugin
            line_prepender_to_file(filenamemsg, "0") # 0=asid, 1=heuristic, 2=threaded, 

        if (len(key_taps)) > 0:
            # Create tap points file for key
            filenamekey = outfileprefix + "_" + comprehendedCaller['entrypoint'] + "_keys.tap"
            create_tappoints_file(filenamekey, key_taps)
            # Add the stack type to the tap point file to make it easy for those who take the file directly as input for the textprinter plugin
            line_prepender_to_file(filenamekey, "0") # 0=asid, 1=heuristic, 2=threaded, 

        logging.info("Analyzer finished analyzing trace of %s bytes at %s" % (func_stats_size, datetime.now()))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Analyze a func_stats file for crypto elements')
    parser.add_argument('-fs', '--stats', help='output file of the func_stats plugin')
    parser.add_argument('-c', '--caller', help='the caller to filter by, can be obtained by the randometer')
    parser.add_argument('-sy', '--sym', default=None, help='symbols file to resolve by (optional)')
    parser.add_argument('-st', '--stack', help='stack to filter by (functionstack or callstack)')
    parser.add_argument('-cn', '--conf', help='resolve reporting confusion that may result from a verbose report')
    parser.add_argument('-v', '--verbose', help='verbose reporting')
    parser.add_argument('-o', '--outprefix', help='output files prefix')
    parser.add_argument('-ac', '--aconfig', help='the config for the analyzer')
    args = parser.parse_args()
    main(file=args.stats, caller=args.caller, function_names=args.sym, stack_name=args.stack, res_confusion=args.conf, verbose=args.verbose, outfileprefix=args.outprefix, aconfig=args.aconfig)