import logging
from helper import percentage

def fill_in_result(name, one, r, out):
            if one["entrypoint"] not in out[name]['result']:
                out[name]['result'][one["entrypoint"]] = list()
                out[name]['result'][one["entrypoint"]].append({'instr_count':one["instr_count"], 'ep': one["entrypoint"], 'r': r, 'functionstack': one["functionstack"]})
                out[name]['count'] = out[name]['count'] + 1 if out[name]['count'] else 1
            else:
                out[name]['result'][one["entrypoint"]].append({'instr_count':one["instr_count"], 'ep': one["entrypoint"], 'r': r, 'functionstack': one["functionstack"]})
                out[name]['count'] = out[name]['count'] + 1 if out[name]['count'] else 1

# Print the callstack
def print_callstack(stack, inv_func_map):
    logging.debug("-->Start printing a record result's callstack<---")
    for func in stack:
        if inv_func_map and func.upper() in inv_func_map:
            print("->"),
            print(inv_func_map[func.upper()]),
            print("..)"),
        else:
            print("->"),
            print(func),
    print("") 
    logging.debug("-->End printing a record result's callstack<---")
    
# Print the result under a record
def print_result(entrypoint, k, v, name, name_dict, name_count, verbose, inv_func_map):
    logging.debug("Start printing a record result...")
    for entrypoint in name_dict:
        if entrypoint == str(k):
            print(name + "ep", str(k)),
            print("\n"),
            if verbose == "True":
                for stack in name_dict[str(k)]:
                    print_callstack(stack['functionstack'], inv_func_map)
            print(name + "epcount", len(name_dict[str(k)])),
            print(name + "epcount/aggregated %", percentage(len(name_dict[str(k)]), v['aggregated'])),
            print(name + "_all_count", name_count)
    logging.debug("End printing a record result...")