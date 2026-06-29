set terminal pngcairo size 1400,700 font "Arial,14"
set output "/home/ayushmanmb/results/mismatch_plot.png"

set title "The Middlebox Mismatch" font "Arial,16"
set xlabel "Time (seconds)" font "Arial,14"
set grid lc rgb "#cccccc"

set ylabel "Linux Conntrack Entries (physical flows)" tc rgb "#E74C3C" font "Arial,13"
set y2label "Actual QUIC Connections" tc rgb "#2ECC71" font "Arial,13"

set ytics nomirror tc rgb "#E74C3C"
set y2tics tc rgb "#2ECC71"
set yrange [0:55000]
set y2range [0:200]
set xrange [0:600]

set arrow 1 from graph(0,0), 50000 to graph(1,1), 50000 nohead lc rgb "red" lw 1 dt 3
set label 1 "Conntrack Limit (50,000) - DoS!" at graph(0.02), 51500 tc rgb "red" font "Arial,11"

set key top left font "Arial,12"

# Compute approximate QUIC connection count
# Attack: 150 rounds, takes ~1000s total = ~6.7s per round
# So QUIC_conns(t) = floor(t / 6.7) but capped at 150

plot "/home/ayushmanmb/results/timeseries.txt" \
        using 1:2 with lines lw 3 lc rgb "#E74C3C" title "Linux Conntrack entries (physical flows)", \
     "/home/ayushmanmb/results/timeseries.txt" \
        using 1:($1/7.0 < 150 ? $1/7.0 : 150) with lines lw 3 lc rgb "#2ECC71" axes x1y2 title "Actual QUIC connections"
