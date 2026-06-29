from bcc import BPF
import ctypes, time, socket

prog = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct lat_event {
    u64 latency_ns;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(start_ts, u64, u64);

int trace_enter(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_ts.update(&id, &ts);
    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = start_ts.lookup(&id);
    if (tsp) {
        struct lat_event e = {};
        e.latency_ns = bpf_ktime_get_ns() - *tsp;
        events.perf_submit(ctx, &e, sizeof(e));
        start_ts.delete(&id);
    }
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="nf_conntrack_in", fn_name="trace_enter")
b.attach_kretprobe(event="nf_conntrack_in", fn_name="trace_exit")

class LatEvent(ctypes.Structure):
    _fields_ = [("latency_ns", ctypes.c_uint64)]

latencies = []

def handle_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(LatEvent)).contents
    lat_us = e.latency_ns / 1000.0
    latencies.append(lat_us)

b["events"].open_perf_buffer(handle_event)

print("Measuring default NAT conntrack latency...")
print("Run client traffic now!")

try:
    while True:
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass

# Save results
with open('/home/ayushmanmb/results/latencies_default.txt', 'w') as f:
    f.write("latency_us\n")
    for l in latencies:
        f.write(f"{l:.2f}\n")

import statistics
if latencies:
    s = sorted(latencies)
    print(f"\nDefault NAT: n={len(s)}")
    print(f"avg={statistics.mean(s):.2f}us")
    print(f"median={statistics.median(s):.2f}us")
    print(f"min={min(s):.2f} max={max(s):.2f}")
    print(f"Saved to latencies_default.txt")
