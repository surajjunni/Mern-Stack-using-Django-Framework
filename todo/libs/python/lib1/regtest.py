import re
import sys

def parse_values(data):	
    #line = sys.argv()
    #var1 =  re.findall("is:\d+\.\d+", str(sys.argv))
    var1 =  re.findall("is:\d+\.\d+", str(data))
    var2 =  re.findall("\d+\.\d+", str(var1))
    for i in var2:
	print i
        return i


#if __name__ == '__main__':
#	parse_values(sys.argv)

