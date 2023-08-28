#!/bin/sh
set -e

cat <<EOM
 _____________________________________________________________________________
( =========================================================================== )
(  Welcome to the PoC Docker Container for the ARES 2023 Paper                )
(  "A Generic IoT Quantum-Safe Watchdog Timer Protocol"                       )
(  by Michael Eckel, Tanja Gutsche, Hagen Lauer, and André Rein               )
( =========================================================================== )
( In The 18th International Conference on Availability, Reliability and       )
( Security (ARES 2023), August 29-September 1, 2023, Benevento, Italy.        )
( ACM, New York, NY, USA, 10 pages.                                           )
( https://doi.org/10.1145/3600160.3605169                                     )
(_____________________________________________________________________________)
        \\
         \\              ##        .
          \\       ## ## ##       ==
               ## ## ## ##      ===
           /""""""""""""""""___/ ===
      ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~
           \______ o ____     __/
            \    \  |PoC | __/
             \____\_______/

EOM

exec "$@"
