#!/bin/sh
#
#  The protocol's maximum message size is 2^27, but we'll settle for testing
#  2^24 or so.
#
i=0
stopat=`expr 1024 '*' 1024`
regen=false
outfile=expected_stdout
if ! test -s $outfile ; then
	regen=true
fi
if test "`tail -n 1 $outfile`" != "$stopat of $stopat" ; then
	regen=true
fi
if $regen ; then
	echo -n 018 - Generating data for test...
	: > $outfile
	while test $i -lt $stopat ; do
		i=`expr $i + 1`
		echo $i of $stopat >> $outfile
	done
	echo " done."
fi
