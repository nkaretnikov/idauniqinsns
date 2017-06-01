from idaapi import *

out_file = AskFile(1, "*.txt", "Select output file")
if not out_file:
    Warning("Failed to select output file")
    exit(1)

def prop(start, end, cur):
    return 100 * (cur - start) / (end - start)

start_addr = NextAddr(0)
end_addr   = PrevAddr(BADADDR)
addr       = start_addr
insns_cnt  = 0
uniqs      = set()
pct_max    = -1

while addr != BADADDR:
    pct = prop(start_addr, end_addr, addr)
    if pct > pct_max:
        pct_max = pct
        Message("%d%%, %d insns, %d uniqs\n" %
                (pct_max, insns_cnt, len(uniqs)))
    mnem = GetMnem(addr)
    if mnem != "":
        insns_cnt += 1
        uniqs.add(mnem)
    addr = NextAddr(addr)

uniqs = list(uniqs)
uniqs.sort()
with open(out_file, 'w') as fd:
    for uniq in uniqs:
        fd.write("%s\n" % uniq)