#!/bin/bash

# Quick script to run queries against UAC artefact dumps
# AUTHOR: Robert Lea
# USAGE ./uac-dfextractor.sh name_of_file.tar.gz

# 21/02/2021 - Added dynamic evidence folder naming for when dealing with multiple archives
# 21/02/2021 - Added check for body file before running mactime

#Set tarball filename as DIR variable
DIR=`echo $1 | cut -d . -f 1`
evidence=$DIR/evidence-$DIR

#Extract tar ball and sub tarballs
#Comment out if already extracted
echo 'Extracting tarball'
tar -zxvf $1
echo 'extracting logs.tar.gz'
tar -zxvf $DIR/collected_data/logs/logs.tar.gz -C $DIR/collected_data/logs/
echo 'extracting system_files.tar.gz'
tar -zxvf $DIR/collected_data/system_files/system_files.tar.gz -C $DIR/collected_data/system_files/
echo 'extracting user_files.tar.gz'
tar -zxvf $DIR/collected_data/user_files/user_files.tar.gz -C $DIR/collected_data/user_files/
echo 'Extract complete.'
echo 'dumping required files in 3'
sleep 1
echo '2'
sleep 1
echo '1'
sleep 1
echo 'taking a dump...'


#Make evidence directory
mkdir $evidence

#grep IOCs and pipe to txt file. Replace STRING with what you want to search for. Add/remove as neccessary
grep -ir 'STRING\|STRING\|STRING\|STRING' $DIR/collected_data/logs/ --include '*.log' > $evidence/grep_network_iocs.txt

# grep for logs with binary in them and output to binaries.txt
grep -ir [[:cntrl:]] $DIR/collected_data/logs/var/log/ --include '*.log' > $evidence/binaries.txt

#cron
cat $DIR/collected_data/system_files/etc/crontab > $evidence/crontab.txt
ls -la $DIR/collected_data/system_files/etc/cron.hourly $DIR/collected_data/system_files/etc/cron.daily $DIR/collected_data/system_files/etc/cron.weekly $DIR/collected_data/system_files/etc/cron.monthly > $evidence/allcrons.txt

#copy netstat-a-n.txt to evidence file
cp $DIR/collected_data/network/netstat-a-n.txt $evidence/netstat-a-n.txt

#copy showmount-a.txt to evidence file
cp $DIR/collected_data/network/showmount-a.txt $evidence/showmount-a.txt

# check if body_file exists then do mactime dump of body_file
if test -f "$DIR/collected_data/body_file/body_file.txt"; then
    	echo "Spotted body_file. Doing mactime dump"
	mactime -d -b $DIR/collected_data/body_file/body_file.txt 2021-01-01..2021-02-19 > $evidence/$DIR-mactime-timeline.csv
	else
	echo "No body_file detected. Skipping mactime"
fi
sleep 3


# cat hosts file and dump results to evidence/hosts.txt
cat $DIR/collected_data/system_files/etc/hosts > $evidence/hosts.txt

# dump command lines
find $DIR/collected_data/process/proc/ -name 'cmdline.txt' -exec cat {} + > $evidence/commandline.txt

# dump running processes and commandlines
cp $DIR/collected_data/process/ps.txt $evidence/running_processes.txt
cp $DIR/collected_data/process/ps-auxwww.txt $evidence/running_processes_commandlines.txt

# failed logons
utmpdump $DIR/collected_data/logs/var/log/btmp > $evidence/failed_logons_btmp.txt

# historical logons
utmpdump $DIR/collected_data/logs/var/log/wtmp > $evidence/historical_logons_wtmp.txt

# ssh failures
cat $DIR/collected_data/logs/var/log/secure* $DIR/collected_data/logs/var/log/messages* $DIR/collected_data/logs/var/log/auth* | grep sshd | grep failure > $evidence/ssh_failures.txt

#check for log tampering
if test -e "$DIR/collected_data/logs/var/run/utmp"; then
    	utmpdump $DIR/collected_data/logs/var/run/utmp | grep "\[0\].*1970-01-01" > $evidence/utmp_tamper.txt
	else
	echo "var/log/utmp not found - skipping"
fi
utmpdump $DIR/collected_data/logs/var/log/wtmp | grep "\[0\].*1970-01-01" > $evidence/wtmp_tamper.txt
utmpdump $DIR/collected_data/logs/var/log/btmp | grep "\[0\].*1970-01-01" > $evidence/btmp_tamper.txt

#Users, sudoers, and groups
cat $DIR/collected_data/system_files/etc/sudoers > $evidence/sudoers.txt
cat $DIR/collected_data/system_files/etc/group > $evidence/groups.txt
cat $DIR/collected_data/system_files/etc/passwd > $evidence/users.txt

# Find SSH authorized keys
find $DIR/collected_data/user_files/ -name authorized_keys > $evidence/SSH_keys.txt

# Dump all user bash history
cat $DIR/collected_data/user_files/root/.bash_history $DIR/collected_data/user_files/home/*/.bash_history > $evidence/all_user_bash_history.txt

# Dump all bashrc data
cat $DIR/collected_data/user_files/root/.bashrc $DIR/collected_data/user_files/home/*/.bashrc > $evidence/all_user_bashrc.txt

# Dump all bash profile data
cat $DIR/collected_data/user_files/root/.bash_profile $DIR/collected_data/user_files/home/*/.bash_profile > $evidence/all_user_bash_profiles.txt

echo "Done! Your dumps are in $evidence."


