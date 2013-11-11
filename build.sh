# Mac Only
mkdir geodata
cd geodata
curl -o GeoIPASNum.dat.gz http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip GeoIPASNum.dat.gz
cd ..
mkdir result
gcc -o p2p_delay p2p_delay.c libGeoIP/*.o -lm /usr/lib/libpcap.dylib
