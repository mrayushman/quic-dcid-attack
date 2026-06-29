set terminal pngcairo size 1400,700 font "Arial,14"
set output "/home/ayushmanmb/results/final_comparison.png"

set title "QUIC Connection Tracking: Linux Conntrack vs Our QUIC-Aware T2 Table" font "Arial,16"
set xlabel "Time (seconds)" font "Arial,14"
set grid lc rgb "#cccccc"
set key top left font "Arial,12" spacing 1.5

set xrange [0:600]

set ylabel "Linux Conntrack Entries" tc rgb "#E74C3C" font "Arial,13"
set y2label "Our T2 Logical Connections" tc rgb "#2ECC71" font "Arial,13"
set ytics nomirror tc rgb "#E74C3C"
set y2tics tc rgb "#2ECC71"
set yrange [0:55000]
set y2range [0:20000]

set arrow 1 from 0,50000 to 600,50000 nohead lc rgb "#E74C3C" lw 1 dt 3
set label 1 "Conntrack Limit (50,000)" at 200,51500 tc rgb "#E74C3C" font "Arial,11"

plot "/home/ayushmanmb/results/timeseries_with_system.txt" \
        using 1:2 with lines lw 3 lc rgb "#E74C3C" axes x1y1 \
        title "Linux Conntrack (5-tuple based)", \
     "/home/ayushmanmb/results/timeseries_with_system.txt" \
        using 1:3 with lines lw 3 lc rgb "#2ECC71" axes x1y2 \
        title "Our T2 Table (O-DCID based)"
