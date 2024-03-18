from collections import defaultdict, Counter
from enum import Enum
from helper import removekeysFromDict, sumFieldInDict, percentage
from reporter import fill_in_result
import logging

class CElement(Enum): 
    scheduling = 1
    sbox = 2
    mixing = 3
    initkround = 4 # needs scheduling 
    shifting = 5 # needs mixing 
    kround = 6 # needs initkround

def extract_insnarith(json):
    try:
        return int(json['insn_arith'])
    except KeyError:
        return 0

def extract_maxexecs(json):
    try:
        return int(json['maxexecs'])
    except KeyError:
        return 0
        

# Aggregate a dict
def solve(dataset, group_by_key, sum_value_keys):
    dic = defaultdict(Counter)
    for item in dataset:
        key = item[group_by_key]
        vals = {k:item[k] for k in sum_value_keys}
        dic[key].update(vals)
        if 'functionstack' in item.keys(): # TODO: Why?
            dic[key]['functionstack'] = item['functionstack']
        if 'maxexecs_addr' in item.keys(): # TODO: Why?
            dic[key]['maxexecs_addr'] = item['maxexecs_addr']
    return dic
    
# Get intersection of two sets of base addresses
def base_intersect(record):
    wbases = set()
    for basewrec in record['writes']:
        wbases.add(basewrec['base'])
    rbases = set()
    for baserrec in record['reads']:
        rbases.add(baserrec['base'])
    return rbases.intersection(wbases)
    
# Report main and round routines for eps
def report_routines_func(out_total_result):
    report_routines = dict() 
    routines_dict = dict()
    all_round_list = list()
    all_main_list = list()
    for celement in out_total_result:
        for ep in out_total_result[celement]['result']:
            if ep not in routines_dict:
                routines_dict[ep] = dict()
            round_routines = list() 
            main_routines = list() 
            for item in out_total_result[celement]['result'][ep]:
                if item['r']['record']['functionstack']:
                    rnd = item['r']['record']['functionstack'][-2] # TODO: can be in aconfig
                    round_routines.append(rnd)
                    all_round_list.append(rnd)
                    main = item['r']['record']['functionstack'][-3] # TODO: can be in aconfig
                    main_routines.append(main) 
                    all_main_list.append(main)
            routines_dict[ep]['round'] = round_routines
            routines_dict[ep]['main'] = main_routines
    report_routines['routines_dict'] = routines_dict
    report_routines['all_round_list'] = all_round_list
    report_routines['all_main_list'] = all_main_list
    return report_routines
    
# Find the state base, baseintersect, baseuniqueread 
# The base where length is unchanged in reads and writes and entropy is higher or equal on write 
# Optional: printableChars are less or equal on write
# Note: state addr is the same in all rounds, also the intersec
# TODO: Improve Error Handling: What if there are nulls
def find_state(record):
    result = {}
    statebase = str()
    statebasew = str() # TODO: Not needed, base is the same
    baseintersect = set()
    baseuniqueread = set()

    # TODO: Duplicate
    wbases = set()
    for basewrec in record['writes']:
        wbases.add(basewrec['base'])
        
    baseintersect = base_intersect(record)
    len = int()
    for rbase in record['reads']:
        for wbase in record['writes']:
            if rbase["base"] == wbase["base"]:
                if rbase["len"] == wbase["len"]: # These are potential state bases
                    # A state base entropy must not be lower on writing
                    if wbase["entropy"] >= rbase["entropy"]:
                        statebase = rbase["base"]
                        statebasew = wbase["base"] # This is used to find shifting
                        len = rbase["len"]
        if rbase["base"] not in wbases:
            # If read base not found in writes, means it is unique for reads
            baseuniqueread.add(rbase["base"])
    result['statebase'] = statebase
    result['statebasew'] = statebasew
    result['len'] = len
    result['baseintersect'] = baseintersect
    result['baseuniqueread'] = baseuniqueread
    return result
    
# Find an s box, 
# SBOX reads a lot of single bytes to substitute a state in place, 
# the state is x number of char, for x rounds (records), 
# and it reads the number of chars only once
# NOTE: Besides it also reads the table too, may be in chuncks, that is the other intersect address (its len is equal to unique sum len too)
def find_sbox(record):
    # Get me the state, if it is there
    state_result = find_state(record)
    # NOTE: record['maxexecs'] > 1 and state_result['len'] != 0 and record['maxexecs'] % state_result['len'] == 0 -> works for standalone aes implementation
    # NOTE: record['insn_movs'] / record['insn_arith'] >= 2 -> can be better to determine confusion between other crypto elements e.g., mixing

    # Is it reading single bytes (can be premutation or s-box)
    if len(record['reads']) > len(record['writes']) and record['nreads'] > record['nwrites']:  
        # If there is a state base
        if state_result['statebase']: # still can be premutation or s-box
            aggrReads  = solve(record['reads'], 'base', ['len', 'nulls', 'printableChars'])
            aggrReadsNoIntersection = removekeysFromDict(aggrReads, state_result['baseintersect'], state_result['statebase']) # NOTE: base is there, we need to remove
            
            baseReadsLen = aggrReadsNoIntersection[state_result['statebase']]["len"] 
            baseReadsLenNoNull = aggrReadsNoIntersection[state_result['statebase']]["len"]  - aggrReads[state_result['statebase']]["nulls"]
            
            uniqueReadsLen = sumFieldInDict(aggrReadsNoIntersection, 'len', set([state_result['statebase']])) # the remainder from reads-base
            uniqueReadsLenNoNull = sumFieldInDict(aggrReadsNoIntersection, 'len', set([state_result['statebase']])) - sumFieldInDict(aggrReadsNoIntersection, 'nulls', set([state_result['statebase']])) # the remainder from reads-base

            # If the clean length of base reads equal to the sum of other unique base addresses then that means we have substituted x times
            if  baseReadsLen == uniqueReadsLen or baseReadsLenNoNull == uniqueReadsLenNoNull: # NOTE: baseReadsLenNoNull == uniqueReadsLen or baseReadsLen == uniqueReadsLen: -> an old check
                # That is our s-box
                return {'found':True, 'state': state_result, 'record': record}
            
    return {'found':False, 'state': state_result, 'record': record}

# Find mixing, pretty much same as s-box, same state, same caller, but we will substitute multiple states with arith op
# TODO: Besides it may also read the table in chuncks, that is the other intersect address (its len is equal to unique sum len too)
def find_mixing(record):
    # Get me the state, if it is there
    state_result = find_state(record)
    # Is it reading single bytes (can be premutation or s-box)
    if len(record['reads']) > len(record['writes']) and record['nreads'] > record['nwrites']:
        # If there is a state base
        if state_result['statebase']: # still be premutation or s-box
            aggrReads  = solve(record['reads'], 'base', ['len', 'nulls', 'printableChars'])
            aggrReadsNoIntersection = removekeysFromDict(aggrReads, state_result['baseintersect'], state_result['statebase']) # NOTE: base is there, we need to remove
            
            baseReadsLen = aggrReadsNoIntersection[state_result['statebase']]["len"] 
            baseReadsLenNoNull = aggrReadsNoIntersection[state_result['statebase']]["len"]  - aggrReads[state_result['statebase']]["nulls"]
            
            uniqueReadsLen = sumFieldInDict(aggrReadsNoIntersection, 'len', set([state_result['statebase']])) # the remainder from reads-base
            uniqueReadsLenNoNull = sumFieldInDict(aggrReadsNoIntersection, 'len', set([state_result['statebase']])) - sumFieldInDict(aggrReadsNoIntersection, 'nulls', set([state_result['statebase']])) # the remainder from reads-base

            # if the clean lenth of base reads less than the sum of other unique base addresses then that means we have substituted by shifting to mix columns
            if baseReadsLen < uniqueReadsLen or baseReadsLenNoNull < uniqueReadsLenNoNull: # NOTE: baseReadsLen < uniqueReadsLen or baseReadsLenNoNull < uniqueReadsLen: -> an old check
                # that is our mixer
                return {'found':True, 'state': state_result, 'record': record}
    return {'found':False, 'state': state_result, 'record': record}
    
# Find shifting
def find_shifting(record, mixer):
    # If there is mixing, then we can find the shifting easily, logic is below, we won't enter here unless a mixing is found
    # Get me the state, if it is there
    # NOTE: state_result['len'] != 0 and record['maxexecs'] % state_result['len'] == 0 -> works with custom aes implementation
    state_result = find_state(record)
    for k in mixer: # TODO: It just find it in any one of them, is there a better way?
        for item in mixer[k]: 
            mixing_state = item['r']['state']
            if 'statebasew' in mixing_state:
                # MixCloumns and Shift rows accesses same addresses (with same length)
                if mixing_state['statebasew'] == state_result['statebasew'] and mixing_state['statebase'] == state_result['statebase']:
                    # MixCloumns has more store llvm ops and more arithmatic instructions than shifting
                    if (item['r']['record']['insn_arith'] > record['insn_arith'] and item['r']['record']['llvm_insn_store'] > record['llvm_insn_store']):
                        # That is our shifter
                        return {'found':True, 'state': state_result, 'record': record}
    return {'found':False, 'state': state_result, 'record': record}

def find_expansion(record):
    # An expansion function is basically one that (commented: has no state bases (mostly))
    # One of its unique read(s) is the "key" to be expanded, its length is urlength
    # Then there is a length in writes (explength) that is > urlength, additionally can be explength % maxexecs is urlength
    # Then about entropy, the expanded length is higher than the ur one
    # NOTE: What if the function is in the main routine, which would have a state?
    # TODO: Usually has very high stats e.g, sumexecs, movs, arith
    # TODO: Why does it find expansions for hashing algorithms?
    state_result = find_state(record)
    keyrec = dict()
    #if not state_result['statebase'] and not state_result['statebasew']: # If commented, more recs but not important
    aggrReads  = solve(record['reads'], 'base', ['len', 'nulls', 'printableChars'])
    for uread in state_result['baseuniqueread']: # NOTE: It can also be split to misdirect you
        for write in record['writes']: # NOTE: It can also be split to misdirect you
            # Find the read entropy of the unique read
            tmp_corr_read = dict()
            tmp_pc = str()
            for read in record['reads']:
                if read['base'] == uread:
                    tmp_corr_read = read
                    tmp_pc = read['pc']
            # NOTE: the % maxexecs indicates a ratio b/w write buffers, maxececs, and new data buffers, and differs in other runs e.g., opensslaes (but with == only) 
            # NOTE: the % insn_arith indicates a scale of 10, and 5 is a sweet spot in our dataset
            if (write['len'] > aggrReads[uread]["len"]) and write['entropy'] > tmp_corr_read['entropy']:
                if (write['len'] % record['maxexecs'] >= aggrReads[uread]["len"]) and (record['insn_arith'] % (record['insn_arith'] / 10 ) >= 5):
                    keyrec['keyraddr'] = uread
                    keyrec['keyraddrpc'] = tmp_pc
                    keyrec['keyrlen'] = aggrReads[uread]["len"]
                    keyrec['keywaddrpc'] = write['pc']
                    keyrec['keywaddr'] = write['base']
                    keyrec['keywlen'] = write['len']
                    return {'found':True, 'state':state_result, 'keyrecord': keyrec, 'record': record}
    return {'found':False, 'state':state_result, 'keyrecord': keyrec, 'record': record}
    
def find_addkeyround_init(record, exp):
    # Add round key function initial, basically arith function, that xors the state with a 128 bit key (16 bytes), 
    # For each round, using the expanded key, meaning expanded key len = no. rounds * key size
    # If there is keyexpansion expect addkeyround or vice versa, where in one of it's reads, it gets the round key from the expanded key, with the corresponding size 
    # TODO: It has same traits as sbox, and entropy changes
    state_result = find_state(record) # it has a state but not necessarly in the record where the below logic applies
    for k in exp:  # TODO: just find it in any one of them
        for item in exp[k]:
            keyrecord = item['r']['keyrecord']
            if keyrecord:
                for read in record['reads']:
                    if read['base'] == keyrecord['keywaddr'] and read['len'] == keyrecord['keyrlen']:
                        return {'found':True, 'state': state_result, 'record': record}
    return {'found':False, 'state': state_result, 'record': record}

def find_addkeyround(record, initkround):
    # Add round key function, basically arith function, that xors the state with a 128 bit key (16 bytes), 
    # If there is find_addkeyround_init expect find_addkeyround or vice versa, where in one of it's reads, it gets the write from initkround, with the corresponding size 
    # TODO: It may have same traits as sbox, and entropy changes
    state_result = find_state(record) # It may have a state but not necessarly in the record where the below logic applies
    for k in initkround:  # TODO: Just find it in any one of them, any better way?
        for item in initkround[k]:
            initkroundrec = item['r']['record']
            if initkroundrec and (state_result['len'] != 0):
                for write in initkroundrec['writes']:
                    for read in record['reads']:
                        if read['base'] == write['base'] and read['len'] == write['len']:
                            return {'found':True, 'state': state_result, 'record': record}
    return {'found':False, 'state': state_result, 'record': record}
       
# Find if a name record is found in any of the entrypoints, in any of the ep results
def check_exists_for_a_rec_found(celement_name, out):
    celement_name_clean = str(celement_name).split('.')[1]
    for epk in out[celement_name_clean]['result']:  # Just find it in any entrypoint, in any record
        for item in out[celement_name_clean]['result'][epk]:
            if item['r'] and item['r']['found']:
                return True
    else:
        return False
        
def celement_finder(celement_tofind, prereq_celements, out, aggregatedFilteredStackRecs, filteredStack):
    for k,v in sorted(aggregatedFilteredStackRecs.items(), reverse=True): # Reverse order from actual call order, to find process prerequisites (e.g. mixing before shifting)
        for one in filteredStack: # Get info from original stack
            if one["entrypoint"] == str(k): # Only if key matches entrypoint
                if celement_tofind in prereq_celements:
                   print("CElement you are trying to find is in prerequisite celements!")
                   return None # Deadlock
                else:
                   if (len(prereq_celements) > 0):
                        for celement in prereq_celements:
                            if not check_exists_for_a_rec_found(celement, out):
                                if celement == CElement.scheduling:
                                    scheduling_result = find_expansion(one)
                                    if scheduling_result['found']: 
                                        fill_in_result('scheduling', one, scheduling_result, out)
                                elif celement == CElement.sbox:
                                    sbox_result = find_sbox(one)
                                    if sbox_result['found']: 
                                       fill_in_result('sbox', one, sbox_result, out)
                                elif celement == CElement.mixing:
                                    mixing_result = find_mixing(one)
                                    if mixing_result['found']:
                                        fill_in_result('mixing', one, mixing_result, out)
                                elif celement == CElement.initkround:
                                    initkround_result = find_addkeyround_init(one , out['scheduling']['result'])
                                    if initkround_result['found']:
                                        fill_in_result('initkround', one, initkround_result, out)
                                else:
                                     print("The prerequisite celement is unknown", celement)
                    
                # Now we found prerequisites that we know of, let's find other celements
                if celement_tofind == CElement.initkround:
                    initkround_result = find_addkeyround_init(one, out['scheduling']['result'])
                    if initkround_result['found']: 
                       fill_in_result('initkround', one, initkround_result, out)
                if celement_tofind == CElement.kround: # Ugly copy paste from above
                    kround_result = find_addkeyround(one, out['initkround']['result'])
                    if kround_result['found']:
                        fill_in_result('kround', one, kround_result, out)
                if celement_tofind == CElement.shifting:
                    shifting_result = find_shifting(one, out['mixing']['result'])
                    if shifting_result['found']: 
                        fill_in_result('shifting', one, shifting_result, out)
                # Ugly copy paste from above
                if celement_tofind == CElement.scheduling:
                    scheduling_result = find_expansion(one)
                    if scheduling_result['found']: 
                        fill_in_result('scheduling', one, scheduling_result, out)
                if celement_tofind == CElement.sbox:
                    sbox_result = find_sbox(one)
                    if sbox_result['found']: 
                        fill_in_result('sbox', one, sbox_result, out)
                if celement_tofind == CElement.mixing:
                    mixing_result = find_mixing(one)
                    if mixing_result['found']:
                        fill_in_result('mixing', one, mixing_result, out)
                #else: 
                    #print("CElement is unknown", celement_tofind)
                
# Singular and aggregated comparison between results and also records
def resolve_confusion(name, counter_name, rec, trait, op, aggr):
    if check_exists_for_a_rec_found('Celement.'+counter_name, out_total_result): 
         # CONST
         SPACE = " "
         # Aggregate by entry point
         aggregated = solve(filteredStack, 'entrypoint', ['maxexecs', 'insn_arith', 'llvm_insn_store', 'llvm_insn_load'])
         aggr_ep = dict()
         for key,val in aggregated.items():
            if str(key) == rec["entrypoint"]:
                aggr_ep = val
         
         # find the record with the same index
         instr_count_in_list = None
         
         # prepare vars
         tmp_l = list()
         tmp_l2 = list()
         evaluate = False
         
         # if both names exist in results
         if rec['entrypoint'] in out_total_result[name]['result'] and rec['entrypoint'] in out_total_result[counter_name]['result']:
             # prepare the name list
             for item in out_total_result[name]['result'][rec['entrypoint']]:
                tmp_l.append(item['r']['record'])
             # prepare the counter_name list
             for item in out_total_result[counter_name]['result'][rec['entrypoint']]:
                tmp_l2.append(item['r']['record'])
                if item['r']['record']['instr_count'] == rec['instr_count']:
                    instr_count_in_list = out_total_result[counter_name]['result'][rec['entrypoint']].index(item)
             
             # the string condition to evaluate in case no aggregation is needed, it works by the found index in counter name, comparing it with the record
             condition = str("out_total_result['"+counter_name+"']['result'][rec['entrypoint']]["+str(instr_count_in_list)+"]['r']['record']['"+trait+"']"+SPACE+op+SPACE+"rec['"+trait+"']")
             
             # aggregat all records traits in lists
             aggr_in_list = solve(tmp_l, 'entrypoint', ['maxexecs', 'insn_arith', 'llvm_insn_store', 'llvm_insn_load'])
             aggr_in_list2 = solve(tmp_l2, 'entrypoint', ['maxexecs', 'insn_arith', 'llvm_insn_store', 'llvm_insn_load'])
             
             # the string condition to evaluate (old), by ep aggregation
             #aggr_condition = str("aggr_in_list['"+trait+"']"+SPACE+op+SPACE+"aggr_ep['"+trait+"']")
             
             # the string condition to evaluate comparing the two traits from curr results
             aggr_condition = str("aggr_in_list2['"+trait+"']"+SPACE+op+SPACE+"aggr_in_list['"+trait+"']")
            
             # It can only be debugged when instr_count_in_list is not None
             #logging.debug("singular", eval(str("out_total_result['"+counter_name+"']['result'][rec['entrypoint']]["+str(instr_count_in_list)+"]['r']['record']['"+trait+"']")))
             logging.debug("name %s" % (name))
             logging.debug("counter_name %s" % (counter_name)) 
             logging.debug("trait1_list %s" % (aggr_in_list)) 
             logging.debug("trait2_list(counter) %s" % (aggr_in_list2)) 
             logging.debug("aggr_by_ep %s" % (eval("aggr_ep['"+trait+"']"))) 
            
             if aggr == "False":
                if instr_count_in_list:
                    evaluate = eval(condition)
                else:
                    print("Switch to aggr, instr_count not found in list") # not good, should probably fail
                    evaluate = eval(aggr_condition)
             else:
                evaluate = eval(aggr_condition)
                
         return evaluate
    else:
        return False

# Function that filters caller
def filterCaller(rec, caller):
    if rec['caller'] == caller: #caller from randometer
        return True
    else:
        return False

# Function that filters stack
def filterStack(rec, stack_name, stack_filter):
    if all(elem in rec[stack_name] for elem in stack_filter):
        return True
    else:
        return False

# Function that filters stats
def filterStats(rec, filter_mainrec, writent):
    fitleredw = [x for x in rec["writes"] if x["entropy"] > writent] # entropy on writes, TODO: if split to more
    arith = rec["insn_arith"] > 1 # it needs to have some arithmatic
    maxexecs = rec[filter_mainrec] > 1 # it needs to have a loop
    if len(fitleredw) > 0 and arith and maxexecs:
        return True
    else:
        return False
        
# To track some fields to the max
def track_max_fields(records):
    result = dict()
    maxexecs = 0
    llvm_bb = 0
    for rec in records:
        if rec['maxexecs'] > maxexecs:
            maxexecs = rec['maxexecs']
        if rec['llvm_bb'] > llvm_bb:
            llvm_bb = rec['llvm_bb']
    result['maxexecs'] = maxexecs
    result['llvm_bb'] = llvm_bb
    return result

