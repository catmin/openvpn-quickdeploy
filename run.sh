
if [ $# -ne 1 ]
then
	echo "$0 <server>"
	exit 1
fi

ansible-playbook -i $1, -u sba --ask-pass play.yml
