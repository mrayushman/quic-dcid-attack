set terminal pngcairo size 1400,700 font "Arial,14"
set output "/home/ayushmanmb/results/nat_drops.png"

set title "The Middlebox Mismatch" font "Arial,16"
set xlabel "Time (seconds)" font "Arial,14"
set grid lc rgb "#cccccc"

set ylabel "NAT Failures (Packet Drops)" tc rgb "#E74C3C" font "Arial,13"
set y2label "Conntrack Entries" tc rgb "#888888" font "Arial,13"

set ytics nomirror tc rgb "#E74C3C"
set y2tics tc rgb "#888888"

set yrange [0:800]
set y2range [0:55000]
set xrange [0:900]

set arrow 1 from graph(0,0), second 50000 to graph(1,1), second 50000 nohead lc rgb "red" lw 1 dt 3
set label 1 "Conntrack Limit (50,000)" at graph(0.55), second 48000 tc rgb "red" font "Arial,11"

set key top left font "Arial,12"

plot "/home/ayushmanmb/results/timeseries_run2.txt" \
        using 1:10 with lines lw 3 lc rgb "#E74C3C" title "NAT failures (packet drops)", \
     "/home/ayushmanmb/results/timeseries_run2.txt" \
        using 1:2 with lines lw 2 lc rgb "#888888" dt 2 axes x1y2 title "Conntrack entries"
