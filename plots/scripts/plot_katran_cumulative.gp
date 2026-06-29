set terminal pngcairo size 1200,700 font "Arial,14"
set output "/home/kartan-lb/results/katran_cumulative.png"

set title "Katran LB Failure Under QUIC DCID Rotation\n(Connection established on Pod3 — migrations routed to wrong backends)" font "Arial,14"
set xlabel "Migration Checkpoint" font "Arial,13"
set ylabel "Cumulative Routing Failures (Wrong Backend Hits)" font "Arial,13"
set grid ytics lc rgb "#cccccc"

set yrange [0:25]
set xrange [-0.5:5.5]
set key top left font "Arial,12"

set style data histogram
set style histogram clustered gap 1
set style fill solid 0.8 border lc rgb "black"
set boxwidth 0.8

plot '/tmp/katran_cumulative.txt' \
        using 2:xtic(1) lc rgb "#E74C3C" title "Pod1 Failures (wrong backend)", \
     '' using 3         lc rgb "#E67E22" title "Pod2 Failures (wrong backend)"
