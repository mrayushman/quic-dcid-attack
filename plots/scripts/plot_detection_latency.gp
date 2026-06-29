set terminal pdfcairo size 8,6 font "Arial,14"
set output "/tmp/detection_latency.pdf"

set title "DCID Migration Detection Latency\neBPF vs QLOG-based Approach (100 runs)" font "Arial,16"
set ylabel "Detection Latency (ms) — log scale" font "Arial,14"
set grid ytics lc rgb "#cccccc"
set key off

set xtics ("eBPF-based" 1, "QLOG-based" 2) font "Arial,13"
set xrange [0.5:2.5]
set logscale y
set yrange [0.001:10000]
set boxwidth 0.4
set style fill solid 0.7 border lc rgb "black"

plot '-' using 1:3:2:5:4 with candlesticks lc rgb "#E74C3C" lw 2 whiskerbars 0.4 notitle, \
     '-' using 1:3:2:5:4 with candlesticks lc rgb "#2980B9" lw 2 whiskerbars 0.4 notitle, \
     '-' using 1:2 with points pt 2 ps 3 lc rgb "black" lw 3 notitle
# x  min    Q1      Q3      max
1  0.001  0.020   0.500   346.0
2  6.072  1500.0  4500.0  5669.3
e
# median
1  0.041
2  3152.4
e
