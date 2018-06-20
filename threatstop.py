
import subprocess
import re

# Execute dig command
def parse(cmd):
        cmd=cmd.split()
        proc=subprocess.check_output(cmd)
        return proc

# IP address are extracted from the dig output
def extract_ip(proc, flag=False):
        if flag:
                regex = "((\d{1,3}\.){3}.\d{1,3})"
        else:
                regex="A\\t((\d{1,3}\.){3}.\d{1,3})"
        ip=re.findall(regex,proc)
        ip_address=[i[0] for i in ip]
        return ip_address

# Push the rules in the IP_Table
def ip_tables(ip_address):
        string = parse(cmd='sudo iptables -L')
        exists_ip = extract_ip(string, flag=True)
        for i in ip_address:
                if i not in exists_ip:
                        a=subprocess.check_output(['sudo', 'iptables', '-A','INPUT','-s','%s'%i,'-j','DROP'])
                #subprocess.Popen(['sudo', 'iptables', '-A','INPUT','-s','%s'%i,'-j','DROP'])


def Main():
        given_cmd="dig @54.175.23.149 acls.threatstop.local"
        proc=parse(given_cmd)
        ip_addr=extract_ip(proc)
        ip_tables(ip_addr)
        #print(ip_addr)



if __name__ == "__main__":
        Main()
