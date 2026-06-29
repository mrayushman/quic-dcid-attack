set terminal pdfcairo size 10,7 font "Arial,14"
set output "/home/ayushmanmb/results/packet_processing_overhead.pdf"

set title "Per-Packet Middlebox Processing Overhead\n(100 runs x 10 migrations each)" font "Arial,16"
set ylabel "Processing Time (microseconds)" font "Arial,14"
set grid ytics lc rgb "#cccccc"
set key off

set xtics ("Default\nLinux NAT" 1, "eBPF-based\nApproach" 2, "QLOG-based\nApproach" 3) font "Arial,12"
set xrange [0.5:3.5]
set yrange [0:100]
set boxwidth 0.4
set style fill solid 0.7 border lc rgb "black"

# candlesticks format: x  box_low  whisker_low  whisker_high  box_high
# col:                  1    3           2             5           4
# median as separate line
plot '/tmp/boxplot_data.txt' using 1:3:2:5:4 with candlesticks \
        lc rgb "#2980B9" lw 2 whiskerbars 0.4 notitle, \
     '/tmp/boxplot_data.txt' using 1:6:($6):($6):($6) with candlesticks \
        lc rgb "black" lw 3 whiskerbars 0.4 notitle
