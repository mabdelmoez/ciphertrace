import json, sys, logging, os
from py2neo import Graph, Relationship, Node
from datetime import datetime

def longest(l):
    if(not isinstance(l, list)): return(0)
    return(max([len(l),] + [len(subl) for subl in l if isinstance(subl, list)] +
        [longest(subl) for subl in l]))

def get_property(node, propertyName):
    return node[propertyName] 
    
def update_property(graph, node, propertyName, propertyValue):
    transaction = graph.begin()
    transaction.merge(node)
    node[propertyName] = propertyValue
    transaction.graph.push(node)
    transaction.commit()

def update_label(graph, node, label_list):
    transaction = graph.begin()
    transaction.merge(node)
    node.update_labels(label_list)
    transaction.graph.push(node)
    transaction.commit()
    
def find_as_ep_or_caller_create_caller(graph, name):
    call = None
    find_call_as_ep = list(graph.nodes.match("ep", name=name)) # as ep
    if len(find_call_as_ep) > 0:
        call = find_call_as_ep[0]
        update_label(graph, call, ["ep", "ep_caller"]) # call found as ep, OK as ep_caller, should be updated to ep now.
    else:
        find_call = list(graph.nodes.match("caller", name=name)) # as caller
        if len(find_call) > 0:
            call = find_call[0]
        else:
            call = Node("caller", name=name) # This is the caller node to create
            #call["count"] = 1 # Just in case
    return call

def find_as_ep_or_caller_create_ep(graph, name):
    func = None
    find_ep = list(graph.nodes.match("ep", name=name))
    
    #find_ep_as_caller = list(graph.nodes.match("caller", name=name))
    #if len(find_ep_as_caller) > 0:
    #    func = find_ep_as_caller[0]
    #    update_label(graph, call, ["caller", "caller_ep"]) #OK as caller, ep found as caller, OOPS!!
        ##print("ep found as caller. OOPS!!", name)
    #else:
    if len(find_ep) > 0:
        func = find_ep[0]
        update_property(graph, func, "count", func["count"]+1)
    else:
        func = Node("ep", name=name) # This is the ep node to create
        func["count"] = 1
    return func

def main(graph_file, sym, conn):

    logging.basicConfig(level=logging.INFO, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')

    start_time = datetime.now()
    logging.info("Starting Visualizer for the graph file %s at %s" % (graph_file, start_time))
    
    graph_file_size = os.path.getsize(graph_file)
    logging.info("Reading graph file %s of size %s bytes" % (graph_file, graph_file_size))
    contents = open(graph_file, "r").read() 
    datadictinit = [json.loads(str(item)) for item in contents.strip().split('\n')]
    listOfkeys = ["entrypoint", "functionstack", "instr_count"]
    datadictselected = [{k: v for k, v in item.items() if k in listOfkeys} for item in datadictinit]
    datadict = sorted(datadictselected, key=lambda k: k['instr_count']) 
    callers = []
    eps = []
    logging.debug("Selected data dictionaries by keys: %s" % (listOfkeys))

    url = "bolt://localhost:7687"
    username = "neo4j"
    password = "mypassword"
    if conn:
        logging.info("Connection details are passed as: %s" % (conn))
        conn_arr = conn.split(",")
        url = str(conn_arr[0].strip())
        username = str(conn_arr[1].strip())
        password = str(conn_arr[2].strip())
    else:
        logging.info("Connection details are the default: %s,%s,%s" % (url, username, password))

    if sym:
        logging.info("Reading symbols file %s" % (sym))
        # remove 0000000000 first files first. 
        # TODO: fix the name cut
        func_map =  {str(k): v.replace('0000000000', '').split('\t')[2] for line in open(sym, 'r').readlines() for (k, v) in (line.strip().split(None, 1),)}
        inv_func_map = {v: k for k, v in func_map.items()}
        logging.debug("Resolving names for entrypoints")
        # Translate entrypoints
        for rec in datadict:
            ep = rec['entrypoint']
            if ep.upper() in inv_func_map:
                ep = inv_func_map[ep.upper()].split('(')[0]
            eps.append(ep)
            rec['entrypoint'] = ep
        # Translate finctionstacks
        logging.debug("Resolving names for functionstack")
        for rec in datadict:
            for idx in range(len(rec["functionstack"])):
                caller = rec["functionstack"][idx]
                if caller.upper() in inv_func_map:
                    caller = inv_func_map[caller.upper()].split('(')[0]
                callers.append(caller)
                rec["functionstack"][idx] = caller
        eps_count = len(set(eps)) # TODO: put that below too
        callers_count = len(set(callers))
        logging.info("Count of entrypoints (functions) to visualize: %s" % (eps_count))
        logging.info("Count of entrypoints' callers to visualize: %s", (callers_count))
    else:
        logging.warn("Symbols are not passed, so function names won't be resolved")

    logging.info("Set database connection with URL:%s, Username:%s, Password:%s" % (url, username, password))
    graph = Graph(url, auth=(username, password))
    clean_query_str = "MATCH (n) OPTIONAL MATCH (n)-[r]-() WITH n,r LIMIT 50000 DELETE n,r RETURN count(n) as deletedNodesCount"
    logging.info("Executing the clean query to clean database first, by query: %s" % (clean_query_str))
    clean_query_result = graph.run(clean_query_str).data()
    logging.info("Database cleaned with result: %s" % (clean_query_result))

    logging.info("Plotting the nodes and edges on the graph")

    # TODO: Better error handling?
    for rec in datadict:
        functionsstack = rec["functionstack"][:-1] # Except current cuz we will create it as ep node
        revfunctionsstack = functionsstack[::-1] # Reverse the stack cuz we loop over them as "called by"
        
        # Create first ep, with first caller relationship
        func = find_as_ep_or_caller_create_ep(graph, rec["entrypoint"])
        first_caller = find_as_ep_or_caller_create_caller(graph, revfunctionsstack[0])
        func_called_by_first_caller = Relationship(func, "calledby", first_caller)
        graph.create(func_called_by_first_caller)

        prev_caller = first_caller # Now update the previous caller, so that you hook it while adding the stack to graph
        
        # Add functionstack items to graph
        for one in revfunctionsstack[1:]: # Starting from second
            call = find_as_ep_or_caller_create_caller(graph, one)
            if prev_caller: # If there is a prveious caller, hook it to the one at hand
                prev_caller_call_rl = Relationship(prev_caller, "calledby", call)
                graph.create(prev_caller_call_rl)
            else:
                graph.create(call)
            prev_caller = call # Now update the previous caller
            
    # Let's try to hook up a node we search for to a new node, and another node that exists already.
    #mynode = list(graph.nodes.match("ep", name="4014dc")) # Get me the ep node 4014dc
    #newnode = Node("NEWLABEL", name="TEST")
    #ab = Relationship(mynode[0], "NEWRL", newnode)
    #graph.create(ab)
    #mynode2 = list(graph.nodes.match("caller", name="82872420")) #Get me the ep node 82872420
    #cd = Relationship(mynode[0], "NEWRL2", mynode2[0])
    #graph.create(cd)
    
    logging.info("Visualizer finished plotting graph of %s bytes, plotting %s entrypoints and %s callers at %s" % (graph_file_size, eps_count, callers_count, datetime.now()))
    logging.info("You can go to your Neo4J browser (e.g, http://localhost:7474/browser), and see the graph, executing this query: MATCH (n1)-[r]->(n2) RETURN r, n1, n2")
    
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Visualize the graph file on neo4j')
    parser.add_argument('-g', '--graphfile', help='the graph file to visualize (output of the analyzer)')
    parser.add_argument('-sy', '--sym', default=None, help='symbols file to resolve by (optional)')
    parser.add_argument('-dc', '--conn', default=None, help='neo4j connection details')

    args = parser.parse_args()
    main(graph_file=args.graphfile, sym=args.sym, conn=args.conn)