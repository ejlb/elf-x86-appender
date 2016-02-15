echo "**** $1 ****"
md5sum $1
readelf -h $1  | grep Entry
./detect/detector $1
