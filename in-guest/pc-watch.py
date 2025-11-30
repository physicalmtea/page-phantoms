#!/usr/bin/env python3
import time, sys

INTERVAL = float(sys.argv[1]) if len(sys.argv) > 1 else 0.2

# ANSI 颜色
RED   = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"

def read_meminfo():
    data = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v, *_ = line.split()
            data[k.rstrip(":")] = int(v)
    return data

def read_vmstat():
    data = {}
    with open("/proc/vmstat") as f:
        for line in f:
            k, v = line.split()
            data[k] = int(v)
    return data

def main():
    fields = [
        ("Cached (kB)",         lambda m, v: m.get("Cached", 0)),
        ("Dirty (kB)",          lambda m, v: m.get("Dirty", 0)),
        ("Writeback (kB)",      lambda m, v: m.get("Writeback", 0)),
        ("pgpgin (pages)",      lambda m, v: v.get("pgpgin", 0)),
        ("pgpgout (pages)",     lambda m, v: v.get("pgpgout", 0)),
    ]

    rate_field = "page_reclaim_rate (pages/s)"
    highlight = {"Dirty (kB)", "Writeback (kB)", "pgpgout (pages)", rate_field}

    header = f"{GREEN}Page Cache Monitor (interval={INTERVAL}s){RESET}"
    print(header)
    for name, _ in fields:
        print(f"{name:30}:")
    print(f"{rate_field:30}:")

    move_up = len(fields) + 1
    prev_vals = {}
    prev_vm = read_vmstat()
    prev_time = time.time()

    while True:
        mem = read_meminfo()
        vm = read_vmstat()
        now = time.time()
        sys.stdout.write(f"\033[{move_up}F")

        for name, func in fields:
            val = func(mem, vm)
            color = RED if name in highlight and prev_vals.get(name) != val else GREEN
            sys.stdout.write(f"{name:30}: {color}{val:>14}{RESET}{CLEAR_LINE}\n")
            prev_vals[name] = val

        d_pgfree = vm.get("pgfree", 0) - prev_vm.get("pgfree", 0)
        dt = now - prev_time
        rate = int(d_pgfree / dt) if dt > 0 else 0
        color = RED if rate > 0 else GREEN
        sys.stdout.write(f"{rate_field:30}: {color}{rate:>14}{RESET}{CLEAR_LINE}\n")
        sys.stdout.flush()

        prev_vm = vm
        prev_time = now
        time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
