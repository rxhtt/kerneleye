#!/usr/bin/env bash
echo "[+] Spawning 500 concurrent child processes to test throughput..."
for i in $(seq 1 500); do
    /bin/true &
done
wait
echo "[+] Completed."

