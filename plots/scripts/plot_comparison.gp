set terminal pngcairo size 1200,700 font "Arial,14"
set output "/home/ayushmanmb/results/comparison_plot.png"

set title "QUIC-Aware Connection Tracking: Our T2 vs Linux Conntrack" font "Arial,16"
set xlabel "Time (seconds)" font "Arial,14"
set ylabel "Number of Connection Entries" font "Arial,14"
set grid lc rgb "#cccccc"
set key top left font "Arial,12"

set xrange [0:900]
set yrange [0:55000]

set arrow 1 from 0,50000 to 900,50000 nohead lc rgb "#E74C3C" lw 1 dt 3
set label 1 "Conntrack Limit (50,000)" at 10,51500 tc rgb "#E74C3C" font "Arial,11"

plot "/home/ayushmanmb/results/timeseries_run2.txt" \
        using 1:2 with lines lw 3 lc rgb "#E74C3C" \
        title "Linux Conntrack (default — 5-tuple based)", \
     "/home/ayushmanmb/results/timeseries_run2.txt" \
        using 1:7 with lines lw 3 lc rgb "#2ECC71" \
        title "Our T2 Table (O-DCID based)"
