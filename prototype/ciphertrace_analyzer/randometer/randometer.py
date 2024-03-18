#!/usr/bin/env python

from collections import Counter
from datetime import datetime
import numpy as np
import unigram_hist
import sys, logging

def ent(arr):
    norm = arr.astype('float32')
    row_sums = norm.sum(axis=1)
    norm = norm / row_sums[:, np.newaxis]
    ma = np.ma.log2(norm) * norm
    return -np.array(ma.sum(axis=1))

def chisq(arr):
    work = arr.astype('float')
    expect = ((1/256.)*work.sum(axis=1))[:,np.newaxis]
    work -= expect
    work *= work
    work /= expect
    return work.sum(axis=1)

def write_set_to_file(set, outfile):
    with open(outfile, 'w') as f:
        for item in set:
            f.write('%s\n' % item)

def main(readgram, writegram, readent, writeent, readrand, writerand, asid, ocallers):
    start_time = datetime.now()
    logging.basicConfig(level=logging.INFO, format='\033[0;32m%(asctime)s \033[0;36m%(filename)s:%(funcName)s@%(lineno)d \033[1;33m[%(levelname)s] \033[0;37m%(message)s')

    # Check if there is an ASID
    if asid == 0:
        logging.warn("ASID is not passed. This would be a dry run, no callers for specific ASIDs will be reported.")

    outfile = None
    # Check if there is an outfile for caller
    if ocallers == None:
        logging.warn("Output file is not passed. Default: randometer.out will be created (if callers to be reported-- ASID is passed).")
        outfile = "randometer.out"
    else: 
        outfile = ocallers

    logging.info("Starting Randometer for information measurement at %s" % (start_time))
    logging.info("Reading unigram read file %s" % (readgram))
    reads = unigram_hist.load_hist(open(readgram,'rb'))
    reads = reads[reads['hist'].sum(axis=1) > 500]
    reads = reads[reads['sidFirst'] != 0]
    if (reads['stackKind'].all() != 0):
        reads = reads[reads['sidSecond'] != 0]
    logging.info("Reading unigram write file %s" % (writegram))
    writes = unigram_hist.load_hist(open(writegram,'rb'))
    writes = writes[writes['hist'].sum(axis=1) > 500]
    writes = writes[writes['sidFirst'] != 0]
    if (writes['stackKind'].all() != 0):
        writes = writes[writes['sidSecond'] != 0]

    ## Chi squared test
    logging.info("Computing randomness of read buffers using Chi-Squared test...")
    #read_chi,read_p = scipy.stats.chisquare(reads['hist'].T)
    read_chi = chisq(reads['hist'])
    logging.info("Computing randomness of write buffers using Chi-Squared test...")
    #write_chi,write_p = scipy.stats.chisquare(writes['hist'].T)
    write_chi = chisq(writes['hist'])

    # Entropy for each
    logging.info("Computing read buffer entropy...")
    read_ent = ent(reads['hist'])

    logging.info("Computing write buffer entropy...")
    write_ent = ent(writes['hist'])

    logging.info("Entropy reads: %d writes: %d" % (len(reads),len(writes)))

    # Apply Entropy masks
    logging.info("Applying read entropy mask %s:" % (readent))
    mask = eval('read_ent ' + readent)
    ent_reads = reads[mask]
    
    logging.info("Applying write entropy mask %s:" % (writeent))
    mask = eval('write_ent ' + writeent)
    ent_writes = writes[mask]

    # TODO: take ent_reads, ent_writes into consideration
    # Apply Randomness masks
    logging.info("Applying read rand mask %s:" % (readrand))
    mask = eval('read_chi ' + readrand)
    read_candidates =  reads[mask] # ent_reads[mask]
    read_chi = read_chi[mask] 
    logging.info("Applying write rand mask %s:" % (writerand))
    mask = eval('write_chi ' + writerand)
    write_candidates = writes[mask] # ent_writes[mask]
    write_chi = write_chi[mask]

    # Intersect
    intersection = np.intersect1d(read_candidates[['caller','sidFirst','sidSecond']], write_candidates[['caller','sidFirst','sidSecond']])
    mask = np.in1d(read_candidates[['caller','sidFirst','sidSecond']],intersection)
    read_final = read_candidates[mask]
    read_chi = read_chi[mask]
    mask = np.in1d(write_candidates[['caller','sidFirst','sidSecond']],intersection)
    write_final = write_candidates[mask]
    write_chi = write_chi[mask]

    logging.info("Results: reads: %d, writes: %d" % (len(read_final), len(write_final)))
    logging.debug("================ Writes ================")
    for row in write_final:
        logging.debug("(%08x %08x %08x %08x): %d bytes" % (row['caller'], row['pc'], row['sidFirst'], row['sidSecond'], row['hist'].sum()))
    logging.debug("================ Reads  ================")
    for row in read_final:
        logging.debug("(%08x %08x %08x %08x): %d bytes" % (row['caller'], row['pc'], row['sidFirst'], row['sidSecond'], row['hist'].sum()))

    wcount = Counter(tuple(row) for row in write_final[['caller','sidFirst','sidSecond']])
    rcount = Counter(tuple(row) for row in read_final[['caller','sidFirst','sidSecond']])

    callers = set()
    logging.info("Read x Write combinations by caller:")
    for caller, sidFirst, sidSecond in rcount:
        logging.info("Start reporting combinations for caller: %08x" % (caller))
        print("(%08x %08x %08x): %d x %d combinations" % (caller, sidFirst, sidSecond, rcount[(caller,sidFirst,sidSecond)], wcount[(caller,sidFirst,sidSecond)]))
        read_sizes = read_final['hist'][(read_final['caller'] == caller) & (read_final['sidFirst'] == sidFirst) & (read_final['sidSecond'] == sidSecond)].sum(axis=1)
        print("  Read sizes: ")
        print(", ".join(("%d" % x) for x in read_sizes))
        write_sizes = write_final['hist'][(write_final['caller'] == caller) & (write_final['sidFirst'] == sidFirst) & (write_final['sidSecond'] == sidSecond)].sum(axis=1)
        print("  Write sizes:")
        print(", ".join(("%d" % x) for x in write_sizes))
        print("  Read rand: ")
        print(", ".join(("%f" % x) for x in read_chi[(read_final['caller'] == caller) & (read_final['sidFirst'] == sidFirst) & (read_final['sidSecond'] == sidSecond)]))
        print("  Write rand:")
        print(", ".join(("%f" % x) for x in write_chi[(write_final['caller'] == caller) & (write_final['sidFirst'] == sidFirst) & (write_final['sidSecond'] == sidSecond)]))
        print("  Best input/output ratio (0 is best possible):")
        print(min(np.abs(1-(xx/float(yy))) for xx in read_sizes for yy in write_sizes))
        logging.info("End reporting combinations for caller: %08x" % (caller))
        sidhex = hex(sidFirst).rstrip("L").lstrip("0x") or "0"
        logging.debug("Checking if %s is the same as %s" % (sidhex, asid))
        if str(sidhex) in asid or asid in str(sidhex): # The old check was sidhex == asid, now it is by contains to account for any number of 0s prefixed or suffixed, especially prefixed
            callers.add(hex(caller).rstrip("L").lstrip("0x") or "0") # TODO: could be a problem with 0s
    logging.info("End reporting combinations by callers")
    if asid != 0:
        logging.info("Callers for ASID %s are %s" % (asid, callers))
        write_set_to_file(callers, outfile)
    logging.info("Randometer finished measuring information of %s and %s at %s" % (readgram, writegram, datetime.now()))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run information measurement over unigrams: Get the caller of an asid')
    parser.add_argument('-rg', '--readgram', help='unigram reads file')
    parser.add_argument('-wg', '--writegram', help='unigram writes file')
    parser.add_argument('-re', '--readent', help='entropy reads mask')
    parser.add_argument('-we', '--writeent', help='entropy writes mask')
    parser.add_argument('-rr', '--readrand', help='randomness reads mask')
    parser.add_argument('-wr', '--writerand', help='randomness writes mask')
    parser.add_argument('-sid', '--asid', default=0, help='the ASID to get its caller')
    parser.add_argument('-oc', '--ocallers', help='output file of callers')
    args = parser.parse_args()
    main(readgram=args.readgram, writegram=args.writegram, readent=args.readent, writeent=args.writeent, readrand=args.readrand, writerand=args.writerand, asid=args.asid, ocallers=args.ocallers)