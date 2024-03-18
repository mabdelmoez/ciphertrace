#!/bin/bash

#TODO: Fix calculation err for duration

# Read the README.md for more info.

# Set panda2m-system-i386
#alias panda2m-system-i386=/home/osboxes/panda-re.old/panda-re/panda/build/i386-softmmu/panda-system-i386
# Set panda2m-system-x86_64
#alias panda2m-system-x86_64=/home/osboxes/panda-re.old/panda-re/panda/build/x86_64-softmmu/panda-system-x86_64

# Crypto #1
# rc4.exe			encrypt.exe      c2.exe        tf.exe       openssl.exe         calc.exe:mspaint.exe         encrypt
# "rc4"				"aes128"      "serpent128"    "tf256"      "opensslaes256"     "calcpaint_nointernet"      "daes128enc"
# "0da2a000"	"30249000"    "31ce0000"     "30a98000"      "2ebe6000"          "5b679000:5c4ab000"     "0fb45000:08ca0000"
# Crypto #2
# hsh.exe 1			hsh.exe 2      hsh.exe 3        hsh.exe 4
# "dbj2"				 "md5"         "sha256"        "hmacsha256" 
# "58562000"	  "57836000"    "55b17000"        "555d1000" 
declare -a REPLAYS=("dbj2"          "md5"       "sha256"    "hmacsha256")
declare -a ASIDS=("58562000"    "57836000"    "55b17000"    "555d1000")
#declare -a REPLAYS=("rc4"        "aes128"    "serpent128"    "tf256"    "opensslaes256"    "daes128enc"       "calcpaint_nointernet"    "dbj2"          "md5"       "sha256"    "hmacsha256") 
#declare -a ASIDS=  ("0da2a000"	"30249000"    "31ce0000"     "30a98000"      "2ebe6000"    "0fb45000:08ca0000"  "5b679000:5c4ab000"    "58562000"    "57836000"    "55b17000"    "555d1000" )   

# Ransomware
# Running: conti.bin...exe   doppel1_...exe maze....bin.sample   netwalker.exe   petya.A.ex   revil.notpacked.exe   ryuk.bin....exe
# Analyzing: 
# --For petya and revil, only the second spawn, due to more activity.
# --For ryuk, only svchost2,cmd2,explorer, due to more activity. Others showed 0 high-arith callers.
# conti -> svchost2:conti.bin.eae8
# paymer -> svchost2:doppel1_3795a2
# maze -> svchost2:maze
# netwalker -> svchost:netwalker
# petya -> svchost2:Petya.A:Petya.A2:
# revil -> svchost2:revil.notpacke:revil.notpacke2
# ryuk -> svchost2:cmd2:explorer:rTJIs:rTJIs2:ryuk.bin.23f8a
#declare -a ASIDS=("66647000:4daa4000"	"66c99000:58352000"     "66946000:b444c000"      "66a3f000:21811000"    "69551000:47f83000:72d4e000"  "66a49000:59c39000:582cf000"   "68fb7000:aadd8000:63e34000:5b540000:8267a000:5c6a3000")    

read -p "Execute analysis or asidstory? Enter 1 for asidstory: " option
read -p "Light verifier mode or default: Enter 1 for light: " vmode

run_string_search(){
	REPLAY=$1
	echo "Running stringsearch"
	cp searchterms.txt enc_search_strings.txt
	sed -i 's/ /:/g' enc_search_strings.txt
	#if [[ $REPLAY =~ "d" ]]
	#	then
	#		panda2m-system-x86_64 -m 256 -replay $REPLAY -panda stringsearch:name=enc
	#	else
			panda2m-system-i386 -m 4G -replay $REPLAY -panda stringsearch:name=enc
	#fi
}

run_verifier_light(){
	REPLAY=$1
	ASID=$2
	echo "Running CipherTrace's Verifier Light for REPLAY $REPLAY and ASID $ASID with CipherTrace Analyzer's output and stringsearch"
	python ../ciphertrace_analyzer/verifier/verifierlight.py --tapdir . --matchesfile enc_string_matches.txt
}

run_analysis() {
	REPLAY=$1
	ASID=$2
	cd $REPLAY
	echo "pwd:" 
	pwd
	DATAIDX=23
	#echo "Running unigrams func_stats for $REPLAY and ASID $ASID"
	#if [[ $REPLAY =~ "d" ]]
	#	then
	#		panda2m-system-x86_64 -m 256 -replay $REPLAY -panda unigrams
	#		panda2m-system-x86_64 -m 256 -replay $REPLAY -panda func_stats:asids=0x$ASID,hex=true,call_limit=200,stack_limit=16
	#	else
	#		panda2m-system-i386 -m 4G -replay $REPLAY -panda unigrams
	#		panda2m-system-i386 -m 4G -replay $REPLAY -panda func_stats:asids=0x$ASID,hex=true,call_limit=200,stack_limit=16
	#fi
	echo "Running CipherTrace's Randometer with unigrams output"
	python ../ciphertrace_analyzer/randometer/randometer.py --readgram unigram_mem_read_report.bin --writegram unigram_mem_write_report.bin --readent '> 0' --writeent '> 0' --readrand '> 10000' --writerand '< 1000' --asid $ASID --ocallers randometer.out # regardless if asid has starting 00s
	run_string_search $REPLAY
	while IFS= read -r line; do
			CALLER=$line
			echo "Running CipherTrace's Analyzer for CALLER $CALLER and REPLAY $REPLAY and ASID $ASID with func_stats output"
			python ../ciphertrace_analyzer/analyzer/analyzer.py --stats func_stats --caller $CALLER --stack functionstack --conf False --verbose False --outprefix $REPLAY --aconfig "maxexecs, 3, 1.0" #--sym func_db # note: caller must not start with 00s
			echo "Duration (excl. verifier): $((($(date +%s)-$start)/60)) minute(s) for REPLAY $REPLAY and ASID $ASID and CALLER $CALLER"
			count=`ls -1 *.tap 2>/dev/null | wc -l`
			if [ $count != 0 ]
			then 
				if [ $vmode == 1 ]; then
						run_verifier_light $REPLAY $ASID
				else
					run_verifier_light $REPLAY $ASID
					for i in *.tap; do
							echo "Running textprinter for TAP $i and REPLAY $REPLAY and ASID $ASID with CipherTrace Analyzer's output"
							[ -f "$i" ] || break
							cp $i tap_points.txt
							#if [[ $REPLAY =~ "d" ]]
							#then
							#	DATAIDX=9
								#panda2m-system-x86_64 -m 256 -replay $REPLAY -panda callstack_instr -panda textprinter
							#else
								DATAIDX=23
								panda2m-system-i386 -m 4G -replay $REPLAY -panda callstack_instr -panda textprinter
							#fi
							echo "Running CipherTrace's Verifier with textprinter output"
							for ((i=0;i<=DATAIDX;i++)); do
								python ../ciphertrace_analyzer/verifier/verifier.py --searchterms searchterms.txt --readbuffers read_tap_buffers.txt.gz --writebuffers write_tap_buffers.txt.gz --dataidx $i; 
							done
					done
				fi
			else
				echo "There are no tap files to check for caller $CALLER and replay $REPLAY"
			fi 
			echo "Duration: $((($(date +%s)-$start)/60)) minute(s) for REPLAY $REPLAY and ASID $ASID and Caller $CALLER"
	done < randometer.out
	cd ..
}
echo "NOTE: Duration is INCREMENTAL."
if [ $option == 1 ]; then
  echo "Runing asidstory on ${REPLAYS[*]} "
	for replayname in ${REPLAYS[*]}
	do
		cd $replayname
		echo "pwd:" 
		pwd
		if [[ $replayname =~ "d" ]]
		then
			echo "Running asidstory for $replayname is not supported, run it manually, and determine the proper os profile for the osi plugin"
		else
			panda2m-system-i386 -m 4G -replay $replayname -panda osi -os windows-32-7 -panda asidstory:width=180 
		fi
		cd ..
	done
else
    echo "Runing analysis on ${REPLAYS[*]}"
		for i in "${!REPLAYS[@]}"; do
			REPLAY=${REPLAYS[i]}
			ASID=${ASIDS[i]}
			echo "Replay $REPLAY and ASID $ASID"
			start=`date +%s`
			if [[ $ASID =~ ":" ]]
			then
				IFS=':' # : is set as delimiter
				read -ra REPLAY_ASIDS <<< "${ASIDS[i]}" # read into an array as tokens separated by IFS
				for i in "${!REPLAY_ASIDS[@]}"; do
					ASID=${REPLAY_ASIDS[i]}
					run_analysis $REPLAY $ASID
				done
			else
				run_analysis $REPLAY $ASID
			fi
			echo "Duration: $((($(date +%s)-$start)/60)) minute(s) for REPLAY $REPLAY and ASID $ASID"
			#end=`date +%s`
			#runtime=$((end-start))
		done
fi
