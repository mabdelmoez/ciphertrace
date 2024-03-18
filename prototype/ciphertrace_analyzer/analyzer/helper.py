from collections import Counter
import os

# Remove keys from dict
def removekeysFromDict(d, keys, state):
    r = dict(d)
    for k in keys:
        if k != state:
            del r[k]
    return r
        
# Sum a field in dict with keys exception
def sumFieldInDict(d, field, keys):
    len = 0
    for k in d:
        if k not in keys:
            len = len + d[k][field]
    return len


# Function to find most frequent element in a list 
def most_frequent(List): 
    if List:
        return max(set(List), key = List.count)
    else:
        return None
        
# Function to find most frequent element in a list 
# Considers more than 1 common (max 3)
def most_frequent_2(List): 
    occurence_count = Counter(List) 
    result = []
    for ele in occurence_count.most_common(3):
      result.append(ele[0])
    return result

# Function to find most frequent n elements in a list
def most_frequent_n(List, n):
    base_counter = {}
    for length in List:
        if length in base_counter:
            base_counter[length] += 1
        else:
            base_counter[length] = 1
    popular_lengths = sorted(base_counter, key = base_counter.get, reverse = True)
    return popular_lengths[:n]

# Helper to find percentage
def percentage(part, whole):
    return 100 * float(part)/float(whole)

def create_tappoints_file(filename, taps):
    mode = 'a+'
    if os.path.exists(filename):
        mode = 'a' # append if already exists
    else:
        mode = 'w' # make a new file if not
    tapfile = open(filename, mode)
    for tap in taps:
        tapfile.write(tap)
    tapfile.close

# Helper to prepend a line to file
def line_prepender_to_file(filename, line):
    with open(filename, 'r+') as f:
        if f.readline() != "0":
            content = f.read()
            f.seek(0,0)
            f.write(line.rstrip('\r\n') + '\n' + content)