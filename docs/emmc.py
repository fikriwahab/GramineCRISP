import socket
import sys

import time
import scipy.stats as stats

if len(sys.argv) < 2:
    port = 8889
else:
    port = int(sys.argv[1])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', port))

usleep = lambda x: time.sleep(x/1000000.0)

mc = 0
current_leader = 0
crash_count = 0
msg_stored = "-"
start = time.time()
last_ev = time.time()

# write data from real emmc
mean_w = 19971.69
min_w = 4943
max_w = 48470
stddev_w = 343.39
dist_w = stats.truncnorm((min_w - mean_w) / stddev_w, (max_w - mean_w) / stddev_w, loc=mean_w, scale=stddev_w)

# read data from real emmc
mean_r = 3891.65
min_r = 2960
max_r = 6075
stddev_r = 545.80
dist_r = stats.truncnorm((min_r - mean_r) / stddev_r, (max_r - mean_r) / stddev_r, loc=mean_r, scale=stddev_r)

while True:
    data, addr = s.recvfrom(1024)
    this_ev = time.time()
    print('[%f] Got connection from' %(this_ev - last_ev), addr)
    if this_ev - last_ev > 1:
        last_ev = time.time()
    cmd_str = data.decode('utf-8')

    if str(cmd_str) == "READ_MC":
        usleep(dist_r.rvs())
        s.sendto(bytes("%d" %mc, 'utf-8'), addr)
    elif str(cmd_str) == "READ_LEADER":
        usleep(dist_r.rvs())
        s.sendto(bytes("%d" %current_leader, 'utf-8'), addr)
    elif str(cmd_str).startswith("INC_MC"):
        usleep(dist_w.rvs())
        current_leader = int(str(cmd_str).split(":")[1]);
        print("Candidate %d tried to increase MC" %current_leader)

        mc += 1
        s.sendto(bytes("%d" %mc, 'utf-8'), addr)
    elif str(cmd_str).startswith("CLAIM_MC"):
        usleep(dist_w.rvs())
        current_leader = int(str(cmd_str).split(":")[1]);
        print("Candidate %d tried to claim MC" %current_leader)

        mc += 1
        crash_count += 1
        s.sendto(bytes("%d" %mc, 'utf-8'), addr)
    elif str(cmd_str) == "READ_CRASH":
        usleep(dist_r.rvs())
        s.sendto(bytes("%d" %crash_count, 'utf-8'), addr)
    elif str(cmd_str) == "RESET_CRASH":
        usleep(dist_w.rvs())
        crash_count = 0
        mc += 1
        s.sendto(bytes("%d" %crash_count, 'utf-8'), addr)
    ### below is RAFT command ###
    elif str(cmd_str) == "MSG_READ":
        usleep(dist_r.rvs())
        s.sendto(bytes("%s" %msg_stored, 'utf-8'), addr)
    elif str(cmd_str).startswith("MSG_INC_MC"):
        usleep(dist_w.rvs())
        current_leader = int(str(cmd_str).split(":")[1])
        msg_stored = str(cmd_str).split(":")[2]
        print("Candidate %d put msg %s" %(current_leader, msg_stored))

        mc += 1
        s.sendto(bytes("%d" %mc, 'utf-8'), addr)
    else:
        print("other: %s" % str(cmd_str))
        s.sendto(bytes("nay", 'utf-8'), addr)

    print("\t\t>> %s| MC:%d | crash:%d | last_msg:%s" %(cmd_str, mc, crash_count, msg_stored))
